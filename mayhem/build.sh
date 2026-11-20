#!/usr/bin/env bash
# mayhem/build.sh — build Angie twice and the in-process fuzz harnesses.
#   objs/fuzz : sanitized (ASan+UBSan, SanCov) build; its objects are linked into
#               every harness (mayhem/fuzz/ngx_fuzz.c, one binary per FUZZ_MODE)
#   objs/test : normal build (objs/test/angie) for mayhem/test.sh (upstream's Perl suite)
# Both build dirs live under /objs/, which upstream's .gitignore already ignores.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
cd "$SRC"

MODULES="--with-http_v2_module --with-http_realip_module --with-http_sub_module
 --with-http_addition_module --with-http_gunzip_module --with-http_mp4_module
 --with-http_flv_module --with-http_slice_module --with-http_auth_request_module
 --with-http_dav_module --with-http_ssl_module --with-mail --with-stream
 --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module
 --with-stream_mqtt_preread_module --with-stream_rdp_preread_module --with-pcre"

# configure is re-run only when its inputs change (re-runnable build, SPEC 6.2 item 9)
configure_once() {
  local dir="$1" ccopt="$2" ldopt="$3"
  local stamp="$dir/.mayhem-configure" want
  want="$(printf '%s\n' "$CC" "$ccopt" "$ldopt" $MODULES | sha256sum)"
  if [ -f "$dir/Makefile" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$want" ]; then return 0; fi
  ./configure --builddir="$dir" --with-cc="$CC" --with-cc-opt="$ccopt" --with-ld-opt="$ldopt" $MODULES
  printf '%s' "$want" > "$stamp"
}

# UBSan relaxations (everything else stays halting): nginx/Angie deliberately use unaligned
# loads/stores on x86 (NGX_HAVE_NONALIGNED: ngx_http_v2_write_uint32 and friends) and call
# ngx_cpymem(dst, NULL, 0) for empty values (e.g. ngx_http_log_module.c), both of which UBSan
# reports on every request. Only `alignment` and `nonnull-attribute` are turned off.
UBSAN_RELAX="-fno-sanitize=alignment,nonnull-attribute"
SANITIZER_FLAGS="$SANITIZER_FLAGS $UBSAN_RELAX"

# 1) sanitized build of the project (the fuzzed code), with coverage instrumentation
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -Wno-error"
configure_once objs/fuzz "$FUZZ_CFLAGS" "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
make -f objs/fuzz/Makefile -j"$MAYHEM_JOBS" objs/fuzz/angie

# 2) harnesses: link every object of the sanitized build except main()
objcopy --redefine-sym main=angie_main_unused objs/fuzz/src/core/nginx.o objs/fuzz/nginx_nomain.o
OBJS=$(find objs/fuzz/src -name '*.o' ! -path objs/fuzz/src/core/nginx.o | sort)
OBJS="$OBJS objs/fuzz/ngx_modules.o"
LIBS=$(awk '/\$\(LINK\) -o objs\/fuzz\/angie/{f=1} f&&/^$/{exit} f' objs/fuzz/Makefile \
       | grep -o -- ' -l[a-z0-9_+-]*' | tr '\n' ' ')
[ -n "$LIBS" ] || { echo "build.sh: could not read link libraries from objs/fuzz/Makefile" >&2; exit 1; }
INCS="-I src/core -I src/event -I src/event/modules -I src/event/quic -I src/os/unix -I src/http -I src/http/v2 -I src/http/modules -I src/mail -I src/stream -I objs/fuzz"
WRAP="-Wl,--wrap=listen -Wl,--wrap=bind -Wl,--wrap=connect -Wl,--wrap=setsockopt -Wl,--wrap=shutdown -Wl,--wrap=chmod -Wl,--wrap=chown -Wl,--wrap=getpwnam -Wl,--wrap=getgrnam"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o objs/fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o objs/fuzz/standalone_main.o

TARGETS="http_request:1 http2_request:2 http_proxy_protocol:3 http_proxy_reply:4 grpc_reply:5
 proxy_v2_reply:6 fastcgi_reply:7 mail_imap:8 mail_pop3:9 mail_smtp:10
 stream_mqtt_preread:11 stream_rdp_preread:12 stream_ssl_preread:13
 uwsgi_reply:14 scgi_reply:15 memcached_reply:16 mp4_file:17 ssi_file:18
 mail_imap_proxy_reply:19 mail_pop3_proxy_reply:20 mail_smtp_proxy_reply:21"
for t in $TARGETS; do
  name=${t%%:*}; mode=${t##*:}
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -DFUZZ_MODE=$mode $INCS \
      -c mayhem/fuzz/ngx_fuzz.c -o objs/fuzz/fuzz_$name.o
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $WRAP objs/fuzz/fuzz_$name.o \
      objs/fuzz/lsan_off.o objs/fuzz/nginx_nomain.o $OBJS $LIBS -o "$SRC/fuzz_$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $WRAP objs/fuzz/fuzz_$name.o objs/fuzz/standalone_main.o \
      objs/fuzz/lsan_off.o objs/fuzz/nginx_nomain.o $OBJS $LIBS -o "$SRC/fuzz_$name-standalone"
done

# 3) normal build for the functional suite (no sanitizers)
configure_once objs/test "-O1 $COVERAGE_FLAGS" "$COVERAGE_FLAGS"
make -f objs/test/Makefile -j"$MAYHEM_JOBS" objs/test/angie
