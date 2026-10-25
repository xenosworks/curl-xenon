/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/*
 * Checks libcurl on the Xbox 360 through xsdk (docs/README-xsdk.md). It walks
 * a homebrew store's path against xsdk's tools/net_http.py, which
 * net_http.txt beside the title names as "<PC address> <HTTP port>", HTTPS on
 * the next port, and logs PASS or FAIL for each check, the download rates,
 * then "tests: <passed> passed, <failed> failed". curl_check_break.txt beside
 * it names one check to break on purpose.
 */
#include <curl/curl.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <xsdk/splash.h>
#include <xsdk/xam.h>

#include "cJSON.h"

#define HOST_FILE "net_http.txt"
#define BREAK_FILE "curl_check_break.txt"
/* What the round trip sent, left for the run launched back */
#define LAUNCHED_FILE "curl_check_launched.bin"
#define PC_CA "test-ca2.crt"
#define PUBLIC_CA "cacert.pem"
/* launch_target launches this back, from the same folder */
#define SELF "game:\\curl_check.xex"
#define LAUNCH_TARGET "launch_target.xex"
#define ROUND_TRIP "launch: launch_target.xex, downloaded and its SHA-256 " \
  "checked, is launched and launches curl_check back with the data reversed"
#define RESUME_FILE "data_1048576.bin"
#define OLD_TEXT "the old version\n"
#define RATE_PATH "/files/data_8388608.bin"
#define RATE_FILE "hdd:/curl_check_rate.part"
#define UNKNOWN_HOST "http://nothing.invalid/"
#define PUBLIC_DOWNLOAD "https://speed.cloudflare.com/__down?bytes=5000000"
/* 21 MB, which github.com redirects to its storage */
#define GITHUB_DOWNLOAD "https://github.com/xenosworks/dusklight-xenon/"   "releases/download/xenon-beta-1/Dusklight-Xbox360-beta-1.zip"

#define SPLASH_MS 2000
/* Public hosts' handshakes have taken over a second */
#define CONNECT_TIMEOUT_MS 15000L
#define STALL_TIMEOUT_MS 500L
#define STALL_LIMIT_MS 1000
/* A transfer this long without a byte ends, so no run hangs */
#define LOW_SPEED_SECONDS 10L
/* Nothing listens there on the console */
#define CLOSED_PORT 7379
#define FILE_BYTES 100000
#define REDIRECT_BYTES 4096
#define RAISED_BUFFER_BYTES (256 * 1024)
#define CATALOGUE_BYTES 65536
#define MAX_ENTRIES 64
#define NAME_BYTES 64
#define URL_BYTES 256
#define SHA256_BYTES 32
#define CHUNK_BYTES 65536

struct transfer {
  CURL *curl;
  FILE *file;          /* the body goes here, if set */
  char *body;          /* or here, ended by a 0, if it fits body_bytes */
  size_t body_bytes;
  curl_off_t offset;   /* where the body starts in the file it is part of */
  curl_off_t size;     /* bytes received */
  curl_off_t total_us;
  long code;
  int pattern_ok;      /* every byte as net_http.py's data files have them */
  int hashing;
  mbedtls_sha256_context sha;
  int raise_buffer;
  int receive_buffer;  /* SO_RCVBUF as it reads back */
  int looked_for_tls;
  char tls[96];
  char error[CURL_ERROR_SIZE];
};

struct entry {
  char name[NAME_BYTES];
  curl_off_t size;
  unsigned char sha256[SHA256_BYTES];
};

/* {"files": [entry, ...], "launch_target": entry}, launch_target.xex's
   entry there once it is built */
struct catalogue {
  struct entry files[MAX_ENTRIES];
  int count;
  struct entry launch_target;
  int has_launch_target;
};

static int passed;
static int failed;
static char break_name[32];
static char pc[INET_ADDRSTRLEN];
static unsigned int http_port;
static struct curl_slist *resolve;
static struct catalogue catalogue;

static void check(const char *name, int ok)
{
  printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
  if(ok)
    passed++;
  else
    failed++;
}

static int broken(const char *name)
{
  return !strcmp(break_name, name);
}

static long long now_ms(void)
{
  struct timespec now;
  (void)clock_gettime(CLOCK_MONOTONIC, &now);
  return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void read_break(void)
{
  FILE *file = fopen(BREAK_FILE, "r");
  if(file) {
    if(fscanf(file, "%31s", break_name) != 1)
      break_name[0] = 0;
    fclose(file);
  }
  if(break_name[0])
    printf("curl check: broken on purpose: %s\n", break_name);
}

/* The PC from HOST_FILE; https://localhost goes there through
   CURLOPT_RESOLVE, so its certificate's name is checked too */
static int read_host(void)
{
  FILE *file = fopen(HOST_FILE, "r");
  int fields = 0;
  char entry[64];
  if(file) {
    fields = fscanf(file, "%15s %u", pc, &http_port);
    fclose(file);
  }
  if(fields != 2) {
    printf("curl check: %s must hold \"<PC address> <HTTP port>\"\n",
           HOST_FILE);
    return 0;
  }
  snprintf(entry, sizeof(entry), "localhost:%u:%s", http_port + 1, pc);
  resolve = curl_slist_append(NULL, entry);
  return resolve != NULL;
}

/* The URL, or "" if it does not fit */
static const char *pc_url(char *url, int https, const char *path)
{
  int length = https ?
    snprintf(url, URL_BYTES, "https://localhost:%u%s", http_port + 1, path) :
    snprintf(url, URL_BYTES, "http://%s:%u%s", pc, http_port, path);
  return length < URL_BYTES ? url : "";
}

static const char *file_path(char *path, const char *name)
{
  return snprintf(path, URL_BYTES, "/files/%s", name) < URL_BYTES ? path : "";
}

static void look_for_tls(struct transfer *t)
{
  struct curl_tlssessioninfo *info = NULL;
  t->looked_for_tls = 1;
  if(curl_easy_getinfo(t->curl, CURLINFO_TLS_SSL_PTR, &info) == CURLE_OK &&
     info && info->backend == CURLSSLBACKEND_MBEDTLS && info->internals) {
    const mbedtls_ssl_context *ssl = info->internals;
    snprintf(t->tls, sizeof(t->tls), "%s %s", mbedtls_ssl_get_version(ssl),
             mbedtls_ssl_get_ciphersuite(ssl));
  }
}

static size_t on_body(char *data, size_t size, size_t count, void *user)
{
  struct transfer *t = user;
  size_t length = size * count;
  unsigned char expected = (unsigned char)((t->offset + t->size) * 31 + 7);
  size_t i;

  if(!t->looked_for_tls)
    look_for_tls(t);
  for(i = 0; i < length; i++, expected = (unsigned char)(expected + 31)) {
    if((unsigned char)data[i] != expected)
      t->pattern_ok = 0;
  }
  if(t->hashing &&
     mbedtls_sha256_update(&t->sha, (const unsigned char *)data, length))
    return 0;
  if(t->body) {
    if((size_t)t->size + length >= t->body_bytes)
      return 0;
    memcpy(t->body + t->size, data, length);
    t->body[t->size + (curl_off_t)length] = 0;
  }
  if(t->file && fwrite(data, 1, length, t->file) != length)
    return 0;
  t->size += (curl_off_t)length;
  return length;
}

static int on_socket(void *user, curl_socket_t fd, curlsocktype purpose)
{
  struct transfer *t = user;
  int size = RAISED_BUFFER_BYTES;
  socklen_t length = sizeof(t->receive_buffer);
  (void)purpose;
  if(t->raise_buffer &&
     setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))
    printf("curl check: SO_RCVBUF %d failed: %d\n", size, errno);
  if(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &t->receive_buffer, &length))
    t->receive_buffer = -1;
  return CURL_SOCKOPT_OK;
}

/* Starts t on url, its certificates checked against the roots in ca; the
   caller sets t's own fields first */
static int prepare(struct transfer *t, const char *url, const char *ca)
{
  t->pattern_ok = 1;
  if(t->hashing) {
    mbedtls_sha256_init(&t->sha);
    (void)mbedtls_sha256_starts(&t->sha, 0);
  }
  t->curl = curl_easy_init();
  if(!t->curl)
    return 0;
  curl_easy_setopt(t->curl, CURLOPT_URL, url);
  curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, on_body);
  curl_easy_setopt(t->curl, CURLOPT_WRITEDATA, t);
  curl_easy_setopt(t->curl, CURLOPT_SOCKOPTFUNCTION, on_socket);
  curl_easy_setopt(t->curl, CURLOPT_SOCKOPTDATA, t);
  curl_easy_setopt(t->curl, CURLOPT_ERRORBUFFER, t->error);
  curl_easy_setopt(t->curl, CURLOPT_CAINFO, ca);
  curl_easy_setopt(t->curl, CURLOPT_RESOLVE, resolve);
  curl_easy_setopt(t->curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(t->curl, CURLOPT_CONNECTTIMEOUT_MS, CONNECT_TIMEOUT_MS);
  curl_easy_setopt(t->curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
  curl_easy_setopt(t->curl, CURLOPT_LOW_SPEED_TIME, LOW_SPEED_SECONDS);
  return 1;
}

/* Runs t and logs how it went */
static CURLcode run(struct transfer *t, const char *what)
{
  CURLcode result = t->curl ? curl_easy_perform(t->curl) : CURLE_FAILED_INIT;
  if(t->curl) {
    curl_easy_getinfo(t->curl, CURLINFO_RESPONSE_CODE, &t->code);
    curl_easy_getinfo(t->curl, CURLINFO_TOTAL_TIME_T, &t->total_us);
  }
  printf("curl check: %s: %s, HTTP %ld, %" CURL_FORMAT_CURL_OFF_T
         " bytes in %" CURL_FORMAT_CURL_OFF_T " ms%s%s%s%s\n", what,
         curl_easy_strerror(result), t->code, t->size, t->total_us / 1000,
         t->tls[0] ? ", " : "", t->tls, t->error[0] ? ": " : "", t->error);
  return result;
}

static void finish(struct transfer *t, unsigned char *sha256)
{
  if(t->hashing) {
    if(sha256)
      (void)mbedtls_sha256_finish(&t->sha, sha256);
    mbedtls_sha256_free(&t->sha);
  }
  curl_easy_cleanup(t->curl);
}

/* Gets a file of net_http.py's from the PC; returns whether it came whole,
   with size bytes as they should be */
static int get_data(const char *url, curl_off_t size, long follow)
{
  struct transfer t;
  int ok;
  memset(&t, 0, sizeof(t));
  ok = prepare(&t, url, PC_CA);
  if(ok) {
    curl_easy_setopt(t.curl, CURLOPT_FOLLOWLOCATION, follow);
    ok = run(&t, url) == CURLE_OK && t.code == 200 && t.size == size &&
         t.pattern_ok;
  }
  finish(&t, NULL);
  return ok;
}

static void check_http(void)
{
  char url[URL_BYTES];
  char path[URL_BYTES];
  snprintf(path, sizeof(path), "/files/data_%d.bin", FILE_BYTES);
  check("http: a file comes from the PC over HTTP, every byte right",
        get_data(pc_url(url, 0, path), FILE_BYTES, 0));
}

static void check_https_pc(void)
{
  char url[URL_BYTES];
  char path[URL_BYTES];
  struct transfer t;
  int ok;
  snprintf(path, sizeof(path), "/files/data_%d.bin", FILE_BYTES);
  memset(&t, 0, sizeof(t));
  ok = prepare(&t, pc_url(url, 1, path),
               broken("pc_trusts_cacert") ? PUBLIC_CA : PC_CA) &&
       run(&t, url) == CURLE_OK && t.code == 200 && t.size == FILE_BYTES &&
       t.pattern_ok;
  finish(&t, NULL);
  check("https: a file comes from the PC over HTTPS, its certificate checked "
        "against the test CA and the name localhost", ok);
}

/* Gets a public host's front page with cacert.pem's roots; returns curl's
   result */
static CURLcode get_public(const char *url, long *code)
{
  struct transfer t;
  CURLcode result = CURLE_FAILED_INIT;
  memset(&t, 0, sizeof(t));
  if(prepare(&t, url, PUBLIC_CA)) {
    curl_easy_setopt(t.curl, CURLOPT_SSL_VERIFYHOST,
                     broken("verifyhost_off") ? 0L : 2L);
    result = run(&t, url);
  }
  *code = t.code;
  finish(&t, NULL);
  return result;
}

static void check_public(void)
{
  long code;
  CURLcode result = get_public("https://example.com/", &code);
  check("https: example.com answers 200, its certificate checked against "
        "cacert.pem", result == CURLE_OK && code == 200);
  result = get_public("https://wrong.host.badssl.com/", &code);
  check("https: wrong.host.badssl.com, its certificate for another name, is "
        "refused", result == CURLE_PEER_FAILED_VERIFICATION);
}

static void check_redirect(void)
{
  char url[URL_BYTES];
  check("http: a redirect is followed to the file it names",
        get_data(pc_url(url, 0, "/redirect"), REDIRECT_BYTES,
                 broken("follow_off") ? 0L : 1L));
}

static void check_stall(void)
{
  char url[URL_BYTES];
  struct transfer t;
  CURLcode result = CURLE_FAILED_INIT;
  memset(&t, 0, sizeof(t));
  if(prepare(&t, pc_url(url, 0, "/stall"), PC_CA)) {
    if(!broken("no_timeout"))
      curl_easy_setopt(t.curl, CURLOPT_TIMEOUT_MS, STALL_TIMEOUT_MS);
    result = run(&t, url);
  }
  finish(&t, NULL);
  check("http: a response that stalls after its headers ends in "
        "CURLE_OPERATION_TIMEDOUT within a second",
        result == CURLE_OPERATION_TIMEDOUT &&
        t.total_us < STALL_LIMIT_MS * 1000);
}

/* Gets url and returns curl's result */
static CURLcode get(const char *url)
{
  struct transfer t;
  CURLcode result = CURLE_FAILED_INIT;
  memset(&t, 0, sizeof(t));
  if(prepare(&t, url, PC_CA))
    result = run(&t, url);
  finish(&t, NULL);
  return result;
}

static void check_failures(void)
{
  char url[URL_BYTES];
  if(broken("refused_answers"))
    (void)pc_url(url, 0, "/files/data_16.bin");
  else
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", CLOSED_PORT);
  check("http: a closed port gives CURLE_COULDNT_CONNECT",
        get(url) == CURLE_COULDNT_CONNECT);
  check("http: a name that does not exist gives CURLE_COULDNT_RESOLVE_HOST",
        get(broken("unknown_answers") ? "http://example.com/" :
            UNKNOWN_HOST) == CURLE_COULDNT_RESOLVE_HOST);
}

static int from_hex(const char *text, unsigned char *bytes)
{
  int i;
  if(strlen(text) != 2 * SHA256_BYTES)
    return 0;
  for(i = 0; i < SHA256_BYTES; i++) {
    unsigned int byte;
    if(sscanf(text + 2 * i, "%2x", &byte) != 1)
      return 0;
    bytes[i] = (unsigned char)byte;
  }
  return 1;
}

/* Reads one catalogue entry; returns whether it is one */
static int parse_entry(const cJSON *file, struct entry *e)
{
  const cJSON *name = cJSON_GetObjectItemCaseSensitive(file, "name");
  const cJSON *size = cJSON_GetObjectItemCaseSensitive(file, "size");
  const cJSON *sha = cJSON_GetObjectItemCaseSensitive(file, "sha256");
  if(!cJSON_IsString(name) || strlen(name->valuestring) >= NAME_BYTES ||
     !cJSON_IsNumber(size) || size->valuedouble < 0 ||
     !cJSON_IsString(sha) || !from_hex(sha->valuestring, e->sha256))
    return 0;
  strcpy(e->name, name->valuestring);
  e->size = (curl_off_t)size->valuedouble;
  return 1;
}

/* Reads a catalogue; returns whether it is one, with at least one file, and
   leaves c empty if not */
static int parse_catalogue(const char *text, struct catalogue *c)
{
  cJSON *root = cJSON_Parse(text);
  const cJSON *files = cJSON_GetObjectItemCaseSensitive(root, "files");
  const cJSON *target = cJSON_GetObjectItemCaseSensitive(root,
                                                         "launch_target");
  const cJSON *file;
  int ok = cJSON_IsArray(files);
  c->count = 0;
  cJSON_ArrayForEach(file, files) {
    if(c->count == MAX_ENTRIES || !parse_entry(file, &c->files[c->count])) {
      ok = 0;
      break;
    }
    c->count++;
  }
  c->has_launch_target = target && parse_entry(target, &c->launch_target);
  ok = ok && c->count > 0 && (!target || c->has_launch_target);
  if(!ok) {
    c->count = 0;
    c->has_launch_target = 0;
  }
  cJSON_Delete(root);
  return ok;
}

/* Gets a catalogue; returns 1 if it reads as one, 0 if it does not, or -1 if
   it did not come */
static int get_catalogue(const char *path, struct catalogue *c)
{
  char url[URL_BYTES];
  struct transfer t;
  int got = -1;
  memset(&t, 0, sizeof(t));
  t.body = malloc(CATALOGUE_BYTES);
  t.body_bytes = CATALOGUE_BYTES;
  if(t.body) {
    t.body[0] = 0;
    if(prepare(&t, pc_url(url, 0, path), PC_CA) && run(&t, url) == CURLE_OK)
      got = parse_catalogue(t.body, c);
  }
  finish(&t, NULL);
  free(t.body);
  return got;
}

static const struct entry *find_file(const char *name)
{
  int i;
  for(i = 0; i < catalogue.count; i++) {
    if(!strcmp(catalogue.files[i].name, name))
      return &catalogue.files[i];
  }
  printf("curl check: %s is not in the catalogue\n", name);
  return NULL;
}

/* Gets a file the catalogue lists; returns whether its size and SHA-256 are
   the catalogue's */
static int served_as_listed(const struct entry *e)
{
  char url[URL_BYTES];
  char path[URL_BYTES];
  unsigned char sha256[SHA256_BYTES];
  struct transfer t;
  int ok;
  memset(&t, 0, sizeof(t));
  t.hashing = 1;
  ok = prepare(&t, pc_url(url, 0, file_path(path, e->name)), PC_CA) &&
       run(&t, url) == CURLE_OK;
  finish(&t, sha256);
  return ok && t.size == e->size && !memcmp(sha256, e->sha256, SHA256_BYTES);
}

static void check_catalogue(void)
{
  static struct catalogue bad;
  int ok = catalogue.count > 0;
  int i;
  for(i = 0; i < catalogue.count; i++) {
    if(!served_as_listed(&catalogue.files[i])) {
      printf("curl check: %s is not served as listed\n",
             catalogue.files[i].name);
      ok = 0;
    }
  }
  check("catalogue: catalog.json reads with cJSON, and each file it lists is "
        "served with its size and SHA-256", ok);
  check("catalogue: a malformed catalogue is refused",
        get_catalogue("/catalog_bad.json", &bad) == 0);
}

/* Hashes what path holds; returns whether it read it all */
static int hash_file(const char *path, curl_off_t *size,
                     unsigned char *sha256)
{
  mbedtls_sha256_context sha;
  unsigned char *chunk = malloc(CHUNK_BYTES);
  FILE *file = fopen(path, "rb");
  size_t got = 0;
  int ok = chunk && file;
  *size = 0;
  mbedtls_sha256_init(&sha);
  (void)mbedtls_sha256_starts(&sha, 0);
  while(ok && (got = fread(chunk, 1, CHUNK_BYTES, file)) > 0) {
    ok = !mbedtls_sha256_update(&sha, chunk, got);
    *size += (curl_off_t)got;
  }
  ok = ok && !ferror(file) && !mbedtls_sha256_finish(&sha, sha256);
  mbedtls_sha256_free(&sha);
  if(file)
    fclose(file);
  free(chunk);
  return ok;
}

/* Downloads url onto the end of part, resuming from what part holds
   already, then flushes it to the disk; returns curl's result */
static CURLcode download_part(const char *url, const char *part)
{
  struct transfer t;
  CURLcode result = CURLE_FAILED_INIT;
  memset(&t, 0, sizeof(t));
  t.file = fopen(part, "ab");
  if(!t.file) {
    printf("curl check: can't open %s: %d\n", part, errno);
    return CURLE_WRITE_ERROR;
  }
  if(!fseek(t.file, 0, SEEK_END))
    t.offset = ftell(t.file);
  if(prepare(&t, url, PC_CA)) {
    if(t.offset)
      curl_easy_setopt(t.curl, CURLOPT_RESUME_FROM_LARGE, t.offset);
    result = run(&t, url);
  }
  finish(&t, NULL);
  if(fflush(t.file) || fsync(fileno(t.file))) {
    printf("curl check: flushing %s failed: %d\n", part, errno);
    result = CURLE_WRITE_ERROR;
  }
  fclose(t.file);
  return result;
}

/* Puts part in name's place, once it is whole as the catalogue has it */
static int install(const char *part, const char *name, const struct entry *e)
{
  curl_off_t size;
  unsigned char sha256[SHA256_BYTES];
  if(!hash_file(part, &size, sha256) || size != e->size ||
     memcmp(sha256, e->sha256, SHA256_BYTES)) {
    printf("curl check: %s, %" CURL_FORMAT_CURL_OFF_T " bytes, is not %s "
           "as listed\n", part, size, name);
    return 0;
  }
  if(rename(part, name)) {
    printf("curl check: rename(%s, %s) failed: %d\n", part, name, errno);
    return 0;
  }
  return 1;
}

static int write_bytes(const char *path, const void *bytes, size_t length)
{
  FILE *file = fopen(path, "wb");
  int ok = file && fwrite(bytes, 1, length, file) == length;
  if(file && fclose(file))
    ok = 0;
  return ok;
}

static size_t read_bytes(const char *path, void *bytes, size_t length)
{
  FILE *file = fopen(path, "rb");
  size_t got = file ? fread(bytes, 1, length, file) : 0;
  if(file)
    fclose(file);
  return got;
}

static curl_off_t file_size(const char *path)
{
  struct stat info;
  return stat(path, &info) ? -1 : (curl_off_t)info.st_size;
}

static void check_resume(void)
{
  const struct entry *e = find_file(RESUME_FILE);
  char old[sizeof(OLD_TEXT)];
  char url[URL_BYTES];
  char path[URL_BYTES];
  const char *part = RESUME_FILE ".part";
  curl_off_t part_size;
  int ok;

  (void)remove(part);
  ok = e && write_bytes(RESUME_FILE, OLD_TEXT, sizeof(OLD_TEXT));
  snprintf(path, sizeof(path), "/drop/%s", RESUME_FILE);
  ok = ok && download_part(pc_url(url, 0, path), part) != CURLE_OK;
  part_size = file_size(part);
  ok = ok && read_bytes(RESUME_FILE, old, sizeof(old)) == sizeof(OLD_TEXT) &&
       !memcmp(old, OLD_TEXT, sizeof(OLD_TEXT)) && part_size > 0 &&
       part_size < e->size;
  check("download: a dropped download fails, leaving the old file as it was "
        "and its part file", ok);

  ok = ok &&
       download_part(pc_url(url, 0, file_path(path, RESUME_FILE)), part) ==
       CURLE_OK && install(part, RESUME_FILE, e) && file_size(part) < 0 &&
       file_size(RESUME_FILE) == e->size;
  check("download: resumed with Range, the part file is whole, its SHA-256 "
        "the catalogue's, and it is renamed over the old file", ok);
  (void)remove(part);
  (void)remove(RESUME_FILE);
}

/* Downloads launch_target.xex and launches it with its launch data: the path
   to launch back, then bytes, all of which it sends back reversed
   (xsdk:tests/launch_target.c); returns only if it does not launch */
static void launch_round_trip(void)
{
  char url[URL_BYTES];
  char data[XSDK_LAUNCH_DATA_MAX_BYTES];
  const char *part = LAUNCH_TARGET ".part";
  size_t data_bytes;

  (void)remove(part);
  if(!catalogue.has_launch_target ||
     download_part(pc_url(url, 0, "/" LAUNCH_TARGET), part) != CURLE_OK ||
     !install(part, LAUNCH_TARGET, &catalogue.launch_target)) {
    printf("curl check: no launch_target.xex as the catalogue lists it\n");
    check(ROUND_TRIP, 0);
    return;
  }
  memcpy(data, SELF, sizeof(SELF));
  data_bytes = sizeof(SELF) +
    (size_t)snprintf(data + sizeof(SELF), sizeof(data) - sizeof(SELF),
                     "curl_check at %lld ms", now_ms());
  if(!write_bytes(LAUNCHED_FILE, data, data_bytes)) {
    printf("curl check: can't keep the launch data in %s\n", LAUNCHED_FILE);
    check(ROUND_TRIP, 0);
    return;
  }
  printf("curl check: launching %s, which launches %s back\n", LAUNCH_TARGET,
         SELF);
  fflush(stdout);
  if(xsdk_launch(LAUNCH_TARGET, data, data_bytes))
    printf("curl check: xsdk_launch failed: %d\n", errno);
  (void)remove(LAUNCHED_FILE);
  check(ROUND_TRIP, 0);
}

/* Back from launch_target: it sent back what this sent, reversed */
static void check_round_trip(void)
{
  char sent[XSDK_LAUNCH_DATA_MAX_BYTES];
  char back[XSDK_LAUNCH_DATA_MAX_BYTES];
  size_t sent_bytes = read_bytes(LAUNCHED_FILE, sent, sizeof(sent));
  size_t back_bytes = xsdk_launch_data(back, sizeof(back));
  int ok = sent_bytes > sizeof(SELF) && back_bytes == sent_bytes;
  size_t i;
  (void)remove(LAUNCHED_FILE);
  for(i = 0; ok && i < sent_bytes; i++)
    ok = back[i] == sent[sent_bytes - 1 - i];
  printf("curl check: back with %u bytes of launch data, %u sent (%.*s)\n",
         (unsigned int)back_bytes, (unsigned int)sent_bytes,
         sent_bytes > sizeof(SELF) ? (int)(sent_bytes - sizeof(SELF)) : 0,
         sent + sizeof(SELF));
  check(ROUND_TRIP, ok);
}

/* Downloads url into memory, or onto the disk if path is set, and logs the
   rate */
static void log_rate(const char *what, const char *url, const char *ca,
                     int raise_buffer, const char *path)
{
  struct transfer t;
  CURLcode result = CURLE_FAILED_INIT;
  long long start = now_ms();
  long long ms;
  memset(&t, 0, sizeof(t));
  t.raise_buffer = raise_buffer;
  if(path)
    t.file = fopen(path, "wb");
  if(path && !t.file)
    printf("curl check: can't open %s: %d\n", path, errno);
  else if(prepare(&t, url, ca)) {
    curl_easy_setopt(t.curl, CURLOPT_FOLLOWLOCATION, 1L);
    result = run(&t, url);
  }
  if(t.file) {
    if(fflush(t.file) || fsync(fileno(t.file)))
      result = CURLE_WRITE_ERROR;
    fclose(t.file);
    (void)remove(path);
  }
  ms = now_ms() - start;
  finish(&t, NULL);
  if(result || ms <= 0)
    printf("rate: %s: %s\n", what, curl_easy_strerror(result));
  else
    printf("rate: %s: %" CURL_FORMAT_CURL_OFF_T " bytes in %lld ms, %lld "
           "KB/s, SO_RCVBUF %d%s%s\n", what, t.size, ms,
           (long long)t.size * 1000 / 1024 / ms, t.receive_buffer,
           t.tls[0] ? ", " : "", t.tls);
}

/* Step 9 of xsdk's docs/scope/56-store-networking.md */
static void log_rates(void)
{
  char url[URL_BYTES];
  char what[128];
  int https;
  int raise_buffer;
  int disk;
  for(https = 0; https < 2; https++) {
    for(raise_buffer = 0; raise_buffer < 2; raise_buffer++) {
      for(disk = 0; disk < 2; disk++) {
        snprintf(what, sizeof(what), "%s from the PC, %s, %s buffers",
                 https ? "HTTPS" : "HTTP", disk ? "onto hdd:" : "into memory",
                 raise_buffer ? "raised" : "XAM's");
        log_rate(what, pc_url(url, https, RATE_PATH), PC_CA, raise_buffer,
                 disk ? RATE_FILE : NULL);
      }
    }
  }
  log_rate("HTTPS from speed.cloudflare.com, into memory, XAM's buffers",
           PUBLIC_DOWNLOAD, PUBLIC_CA, 0, NULL);
  log_rate("HTTPS from speed.cloudflare.com, into memory, raised buffers",
           PUBLIC_DOWNLOAD, PUBLIC_CA, 1, NULL);
  /* Step 1 of xsdk's docs/scope/63-homebrew-store.md */
  log_rate("HTTPS from a GitHub release, into memory, raised buffers",
           GITHUB_DOWNLOAD, PUBLIC_CA, 1, NULL);
}

static void run_checks(void)
{
  (void)get_catalogue("/catalog.json", &catalogue);

  /* A launch ends this run, and the run launched back logs anew, so the
     round trip comes first */
  if(file_size(LAUNCHED_FILE) >= 0)
    check_round_trip();
  else
    launch_round_trip();

  check_http();
  check_https_pc();
  check_public();
  check_redirect();
  check_stall();
  check_failures();
  check_catalogue();
  check_resume();
  log_rates();
}

int main(void)
{
  (void)xsdk_splash_show(SPLASH_MS);
  printf("curl check: %s\n", curl_version());
  read_break();
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    check("curl: libcurl starts", 0);
  else if(!read_host())
    check("curl check: " HOST_FILE " names the PC", 0);
  else
    run_checks();
  printf("tests: %d passed, %d failed\n", passed, failed);
  curl_slist_free_all(resolve);
  curl_global_cleanup();
  return failed ? 1 : 0;
}
