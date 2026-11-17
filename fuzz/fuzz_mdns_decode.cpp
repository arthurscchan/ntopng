/*
 *
 * (C) 2013-26 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <unistd.h>

#include "ntop_includes.h"

#ifdef INCLUDE_ONEFILE
#include "onefile.cpp"
#endif

/*
 * Fuzzes MDNS::decodePTRResponse(), MDNS::decodeAnyResponse() and
 * MDNS::decodeNetBIOS() (src/MDNS.cpp): the name-resolution response
 * decoders ntopng runs on every UDP reply from mDNS responders, gateways
 * (DNS) and NetBIOS name servers. Responders on the local network are
 * untrusted peers, and the decoders do manual label walks, record skips
 * and fixed-size strncpy()s on their bytes. The decoders are private and
 * only reachable through the UDP resolver loop, so the target goes through
 * fuzzDecodePTRResponse()/fuzzDecodeAnyResponse()/fuzzDecodeNetBIOS(),
 * three thin FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION-guarded wrappers
 * added to src/MDNS.cpp. The MDNS object is created once at
 * initialization; the decoders are pure with respect to its state.
 *
 * Input shape: byte 0 selects the decoder, the rest is the response packet.
 */

AfterShutdownAction afterShutdownAction = after_shutdown_nop;
NetworkInterface *iface;

constexpr const char *PROG_NAME = "ntopng";
static ndpi_protocol ndpiUnknownProtocol;

bool trace_new_delete = false;

static MDNS *mdns_fuzz = NULL;

static void cleanup() {
  if (mdns_fuzz) delete mdns_fuzz;
  if (iface) delete iface;
  if (ntop) delete ntop;
}

/**
 * Set the CLI args for prefs.
 *
 * The function must be called like this:
 * setCLIArgs(Prefs *prefs, int params, const char * ...)
 */
static void setCLIArgs(Prefs *prefs, int params...) {
  if (params == 0) return;

  va_list args;
  va_start(args, params);

  // Get path of the binary itself. This is needed to get the absolute path of
  // the required directories
  char exePath[MAX_PATH + 1];
  ssize_t pathLen = readlink("/proc/self/exe", exePath, MAX_PATH);
  if (pathLen != -1) {
    exePath[pathLen] = '\0';
    ssize_t len = pathLen;
    while (len > 0 && exePath[len] != '/') len--;
    if (len == 0) {
      std::cerr << "Error while crafting the command line. Relative path "
	"have been used."
		<< std::endl;
      exit(1);
    }
    exePath[len] = '\0';
    pathLen = len;
  } else {
    std::cerr << "Error while crafting the command line. Failed to "
      "retrieve the absolute path of the executable."
	      << std::endl;
    exit(1);
  }

  // Create the new argv
  char *new_argv[params];
  for (int i = 0; i < params; ++i) {
    const char *opt = va_arg(args, const char *);

    if (!strstr(opt, "_PATH_")) {
      new_argv[i] = strdup(opt);
    } else {
      // size = pathLen + / + opt - _PATH_ + \0
      size_t size = pathLen + 1 + strlen(opt) - 6 + 1;
      new_argv[i] = (char *)malloc(size);
      int len = snprintf(new_argv[i], size, "%s/%s", exePath, opt + 6);
      if (len <= 0) {
	std::cerr << "Error while crafting the command line. Wrong "
	  "buffer size."
		  << std::endl;
	exit(1);
      }
    }
  }

  prefs->loadFromCLI(params, new_argv);

  // Free arguments
  for (int k = 0; k < params; ++k) free(new_argv[k]);

  va_end(args);
}

const ndpi_protocol getConstNdpiUnknownProtocol() {
  return((const ndpi_protocol)ndpiUnknownProtocol);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Final cleanup
  atexit(cleanup);

  Prefs *prefs = NULL;

  if ((ntop = new (std::nothrow) Ntop(PROG_NAME)) == NULL) _exit(1);
  if ((prefs = new (std::nothrow) Prefs(ntop)) == NULL) _exit(1);

  ntop->getTrace()->set_trace_level(0);
  memset((void*)&ndpiUnknownProtocol, 0, sizeof(ndpiUnknownProtocol));

  setCLIArgs(prefs, 11, PROG_NAME, "-1", "_PATH_docs", "-2", "_PATH_scripts",
	     "-3", "_PATH_scripts/callbacks", "-d", "_PATH_data-dir", "-t",
	     "_PATH_install");

  ntop->registerPrefs(prefs, false);

  ntop->loadGeolocation();

  iface = new NetworkInterface("custom");
  iface->allocateStructures();

  /* One long-lived MDNS object: the decoders are pure with respect to its
   * state, so creating it per input is unnecessary churn. The constructor
   * opens two UDP sockets and starts the one-shot resolver thread. */
  if ((mdns_fuzz = new (std::nothrow) MDNS(iface)) == NULL) _exit(1);

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  char out[1024];
  u_int32_t resolved_ip;
  uint8_t selector;
  u_char packet[512];

  if (len < 2) return 0;

  selector = buf[0] % 3;
  size_t payload_len = len - 1;

  /* Production contract (fetchResolveResponses): responses arrive via
   * recvfrom() into a 512-byte stack buffer and only the datagram length is
   * passed on. The decoders read the fixed DNS header fields before any
   * length check, so the buffer must have that capacity; mirror it with a
   * zeroed 512-byte buffer holding the fuzz payload. */
  if (payload_len > sizeof(packet)) payload_len = sizeof(packet);
  memset(packet, 0, sizeof(packet));
  memcpy(packet, buf + 1, payload_len);

  switch (selector) {
    case 0:
      mdns_fuzz->fuzzDecodePTRResponse((char *)packet, (u_int)payload_len,
                                       out, sizeof(out), &resolved_ip);
      break;
    case 1:
      mdns_fuzz->fuzzDecodeAnyResponse((char *)packet, (u_int)payload_len,
                                       out, sizeof(out));
      break;
    case 2:
    default:
      mdns_fuzz->fuzzDecodeNetBIOS(packet, (u_int)payload_len,
                                   out, sizeof(out));
      break;
  }

  return 0;
}
