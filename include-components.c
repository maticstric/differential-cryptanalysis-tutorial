#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>

const char USAGE[] = "usage: include-components template_file final_html_file";
const char COMPONENT_DELIMITER_START[] = "{{";
const char COMPONENT_DELIMITER_END[] = "}}";

struct Substring {
  char *start;
  char *end;
};

void usage() {
  fprintf(stderr, "%s\n", USAGE);
  exit(1);
}

void print_error() {
  fprintf(stderr, "Error: %s\n", strerror(errno));
  exit(1);
}

char* file_into_buffer(char* path) {
  FILE *f;
  char *buffer;

  f = fopen(path, "r");

  if (f == NULL) { print_error(); }

  if (fseek(f, 0, SEEK_END) == -1) { print_error(); }

  long filesize = ftell(f);
  if (filesize == -1) { print_error(); }

  buffer = malloc(sizeof(char) * (filesize + 1));

  if (fseek(f, 0, SEEK_SET) == -1) { print_error(); }

  size_t new_len = fread(buffer, sizeof(char), filesize, f);

  if (ferror(f) != 0) {
    fprintf(stderr, "%s\n", "Error reading file");
    exit(1);
  }

  buffer[new_len + 1] = '\0';

  fclose(f);

  return buffer;
}

struct Substring get_substring(char *string, char* start_string, char* end_string) {
  char *start = strstr(string, start_string);
  char *end = strstr(string, end_string);

  struct Substring substring = {start, end};

  return substring;
}

char* get_component_path(char *template_buffer, char *template_path_dir) {
  struct Substring substring = get_substring(template_buffer, (char*) COMPONENT_DELIMITER_START, (char*) COMPONENT_DELIMITER_END);

  if (substring.start != NULL && substring.end != NULL) {
    size_t component_path_length = substring.end - substring.start - 1;

    char *component_path = malloc(sizeof(char) * (component_path_length + strlen(template_path_dir) + 1));
    strcpy(component_path, template_path_dir);

    component_path[strlen(template_path_dir)] = '/';
    memcpy(component_path + strlen(template_path_dir) + 1, substring.start + 2, component_path_length - 1);

    component_path[component_path_length + strlen(template_path_dir)] = '\0';

    return component_path;
  }
  
  return NULL;
}

char* include_component(char *template_buffer, char *component_buffer) {
  char *combined_buffer = malloc(sizeof(char) * (strlen(template_buffer) + strlen(component_buffer)));

  struct Substring substring = get_substring(template_buffer, (char*)COMPONENT_DELIMITER_START, (char*)COMPONENT_DELIMITER_END);

  memcpy(combined_buffer, template_buffer, substring.start - template_buffer);
  memcpy(combined_buffer + (substring.start - template_buffer), component_buffer, strlen(component_buffer));
  strcpy(combined_buffer + (substring.start - template_buffer) + strlen(component_buffer), substring.end + strlen(COMPONENT_DELIMITER_END) + 1);

  combined_buffer[(substring.start - template_buffer) + strlen(component_buffer) + (strlen(template_buffer) - (substring.end - template_buffer + strlen(COMPONENT_DELIMITER_END) + 1))] = '\0';

  return combined_buffer;
}

int main(int argc, char *argv[]) {
  if (argc != 3) { usage(); }

  char *template_path = argv[1];
  char *html_path = argv[2];

  char template_realpath[PATH_MAX];
  char *template_path_dir;

  if (realpath(template_path, template_realpath) != NULL) {
    template_path_dir = dirname(template_realpath);
  } else {
    print_error();
  }

  char *template_buffer;
  char *component_buffer;
  char *combined_buffer;

  char *component_path;

  template_buffer = file_into_buffer(template_realpath);
  component_path = get_component_path(template_buffer, template_path_dir);

  if (component_path != NULL) {
    component_buffer = file_into_buffer(component_path);

    combined_buffer = include_component(template_buffer, component_buffer);

    printf("%s", combined_buffer);

    free(combined_buffer);
    free(component_buffer);
  }

  free(component_path);
  free(template_buffer);
}

  //FILE *f;

  //char tmp_path[strlen(path_dir) + 5];
  //strcpy(tmp_path, path_dir);
  //strcat(tmp_path, "/tmp\0");

  //f = fopen(tmp_path, "w");
  //fprintf(f, "%s", combined_buffer);
  //fclose(f);

  //rename(tmp_path, resolved_path);
