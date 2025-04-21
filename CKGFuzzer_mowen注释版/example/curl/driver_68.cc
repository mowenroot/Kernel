#include <stdio.h>
#include <curl/curl.h>

// Function from lib1594.c
CURLcode test_lib1594(char *URL)
{
  struct curl_slist *header = NULL;
  curl_off_t retry;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    return CURLE_FAILED_INIT;
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  res = curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry);
  if(res)
    goto test_cleanup;

#ifdef LIB1596
  /* we get a relative number of seconds, so add the number of seconds
     we're at to make it a somewhat stable number. Then remove accuracy. */
  retry += time(NULL);
  retry /= 10000;
#endif
  printf("Retry-After %" CURL_FORMAT_CURL_OFF_T "\n", retry);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_slist_free_all(header);
  curl_global_cleanup();

  return res;
}

// Function from lib1907.c
CURLcode test_lib1907(char *URL)
{
  char *url_after;
  CURL *curl;
  CURLcode res = CURLE_OK;
  char error_buffer[CURL_ERROR_SIZE] = "";

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  res = curl_easy_perform(curl);
  if(!res)
    fprintf(stderr, "failure expected, "
            "curl_easy_perform returned %ld: <%s>, <%s>\n",
            (long) res, curl_easy_strerror(res), error_buffer);

  /* print the used url */
  if(!curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url_after))
    printf("Effective URL: %s\n", url_after);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

// Function from lib1156.c
CURLcode test_lib1156(char *URL)
{
  struct curl_slist *header = NULL;
  curl_off_t retry;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    return CURLE_FAILED_INIT;
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  res = curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry);
  if(res)
    goto test_cleanup;

#ifdef LIB1596
  /* we get a relative number of seconds, so add the number of seconds
     we're at to make it a somewhat stable number. Then remove accuracy. */
  retry += time(NULL);
  retry /= 10000;
#endif
  printf("Retry-After %" CURL_FORMAT_CURL_OFF_T "\n", retry);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_slist_free_all(header);
  curl_global_cleanup();

  return res;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <URL>\n", argv[0]);
    return 1;
  }

  CURLcode res1 = test_lib1594(argv[1]);
  CURLcode res2 = test_lib1907(argv[1]);
  CURLcode res3 = test_lib1156(argv[1]);

  if (res1 != CURLE_OK || res2 != CURLE_OK || res3 != CURLE_OK) {
    fprintf(stderr, "One or more tests failed\n");
    return 1;
  }

  return 0;
}
