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
 * Fuzzes the ntopng web UI entry point: the mongoose begin_request callback
 * handle_lua_request() (src/HTTPserver.cpp) together with mongoose's own
 * request parser (parse_http_message). Every byte of a request - URI, query
 * string, headers, cookies and POST body - is attacker-controlled on the
 * network-facing HTTP interface, and the handler routes it through REST
 * dispatch, session/CSRF checks and .lua path resolution (see the auth
 * bypass hardening comment inside handle_lua_request).
 *
 * The wiring lives in ntopng_fuzz_http_request() appended to
 * src/HTTPserver.cpp behind FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION: it
 * parses the raw request with the production parser and runs the production
 * handler on a minimal in-memory connection whose responses go to an
 * AF_UNIX socketpair, so no TCP port is bound, no thread is spawned and the
 * flow stays deterministic.
 *
 * Input shape: byte 0 is a mode selector, the rest is the raw HTTP request.
 * Mode 1 appends a missing CRLFCRLF terminator so mutations that break the
 * header/body separator still reach the parser as valid requests.
 */

AfterShutdownAction afterShutdownAction = after_shutdown_nop;
NetworkInterface *iface;

constexpr const char *PROG_NAME = "ntopng";
static ndpi_protocol ndpiUnknownProtocol;

bool trace_new_delete = false;

extern "C" int ntopng_fuzz_http_request(const uint8_t *data, size_t size);

static void cleanup() {
  if (iface) delete iface;
  if (ntop) delete ntop; /* ntop owns and destroys the registered HTTPserver */
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

  /* The HTTP server: the constructor only records options and paths, it
   * does not bind any port (that happens in startHttpServer(), which is
   * deliberately not called here). Registering it and enabling request
   * acceptance lets the production handler run its full dispatch. The
   * registered server is owned and destroyed by Ntop::~Ntop(). */
  {
    HTTPserver *httpserver_fuzz = new (std::nothrow)
        HTTPserver(prefs->get_docs_dir(), prefs->get_scripts_dir());

    if (httpserver_fuzz == NULL) _exit(1);

    ntop->registerHTTPserver(httpserver_fuzz);
    httpserver_fuzz->start_accepting_requests();
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (len < 2) return 0;

  uint8_t mode = buf[0] % 2;

  if (mode == 0) {
    /* Parse and handle the raw request exactly as received. */
    ntopng_fuzz_http_request(buf + 1, len - 1);
  } else {
    /* Same request, but with a guaranteed CRLFCRLF terminator so mutations
     * that break the header/body separator still reach the parser. */
    size_t payload_len = len - 1;
    uint8_t *tmp = (uint8_t *)malloc(payload_len + 4);
    if (tmp == NULL) return 0;
    memcpy(tmp, buf + 1, payload_len);
    memcpy(tmp + payload_len, "\r\n\r\n", 4);
    ntopng_fuzz_http_request(tmp, payload_len + 4);
    free(tmp);
  }

  return 0;
}
