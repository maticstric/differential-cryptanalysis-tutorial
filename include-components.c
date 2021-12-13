#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>

const char USAGE[] = "usage: include-components index.html";
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

char* get_component_path(char *buffer, char *path_dir) {
  struct Substring substring = get_substring(buffer, (char*) COMPONENT_DELIMITER_START, (char*) COMPONENT_DELIMITER_END);

  if (substring.start != NULL && substring.end != NULL) {
    size_t component_path_length = substring.end - substring.start - 1;

    char *component_path = malloc(sizeof(char) * (component_path_length + strlen(path_dir) + 1));
    strcpy(component_path, path_dir);

    component_path[strlen(path_dir)] = '/';
    memcpy(component_path + strlen(path_dir) + 1, substring.start + 2, component_path_length - 1);

    component_path[component_path_length + strlen(path_dir)] = '\0';

    return component_path;
  }
  
  return NULL;
}

void include_component(char *file_buffer, char *component_buffer, char *resolved_path, char *path_dir) {
  char combined_buffer[strlen(file_buffer) + strlen(component_buffer)];

  struct Substring substring = get_substring(file_buffer, (char*)COMPONENT_DELIMITER_START, (char*)COMPONENT_DELIMITER_END);

  memcpy(combined_buffer, file_buffer, substring.start - file_buffer);
  memcpy(combined_buffer + (substring.start - file_buffer), component_buffer, strlen(component_buffer));
  strcpy(combined_buffer + (substring.start - file_buffer) + strlen(component_buffer), substring.end + strlen(COMPONENT_DELIMITER_END) + 1);

  combined_buffer[(substring.start - file_buffer) + strlen(component_buffer) + (strlen(file_buffer) - (substring.end - file_buffer + strlen(COMPONENT_DELIMITER_END) + 1))] = '\0';

  FILE *f;

  char tmp_path[strlen(path_dir) + 5];
  strcpy(tmp_path, path_dir);
  strcat(tmp_path, "/tmp\0");

  f = fopen(tmp_path, "w");
  fprintf(f, "%s", combined_buffer);
  fclose(f);

  rename(tmp_path, resolved_path);
}

int main(int argc, char *argv[]) {
  // MAKE NEW ARGUMENT. ONE FOR FINAL HTML AND ONE FOR TEMPLATE FILE
  if (argc != 2) { usage(); }

  char *path = argv[1];
  char resolved_path[PATH_MAX];
  char *path_dir;

  if (realpath(path, resolved_path) != NULL) {
    path_dir = dirname(resolved_path);
  } else {
    print_error();
  }

  char *buffer;
  char *component_path;
  char *component_buffer;

  buffer = file_into_buffer(resolved_path);
  component_path = get_component_path(buffer, path_dir);

  if (component_path != NULL) {
    component_buffer = file_into_buffer(component_path);

    include_component(buffer, component_buffer, resolved_path, path_dir);

    free(component_buffer);
  }

  free(component_path);
  free(buffer);
}
