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

void get_realpath(char* path, char* _realpath) {
  if (realpath(path, _realpath) == NULL) {
    print_error();
  }
}

char* file_into_buffer(char* path) {
  FILE *f;
  char *buffer = NULL;

  f = fopen(path, "r");

  if (f == NULL) { print_error(); }

  if (fseek(f, 0, SEEK_END) == -1) { print_error(); }

  long filesize = ftell(f);
  if (filesize == -1) { print_error(); }

  buffer = calloc((filesize + 1), sizeof(char));

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

    char *component_path = calloc((component_path_length + strlen(template_path_dir) + 1), sizeof(char));
    strcpy(component_path, template_path_dir);

    component_path[strlen(template_path_dir)] = '/';
    memcpy(component_path + strlen(template_path_dir) + 1, substring.start + 2, component_path_length - 1);

    component_path[component_path_length + strlen(template_path_dir)] = '\0';

    return component_path;
  }
  
  return NULL;
}

char* include_component(char *template_buffer, char *component_buffer) {
  char *combined_buffer = calloc((strlen(template_buffer) + strlen(component_buffer)), sizeof(char));

  struct Substring substring = get_substring(template_buffer, (char*)COMPONENT_DELIMITER_START, (char*)COMPONENT_DELIMITER_END);

  memcpy(combined_buffer, template_buffer, substring.start - template_buffer);
  memcpy(combined_buffer + (substring.start - template_buffer), component_buffer, strlen(component_buffer));
  strcpy(combined_buffer + (substring.start - template_buffer) + strlen(component_buffer), substring.end + strlen(COMPONENT_DELIMITER_END) + 1);

  combined_buffer[(substring.start - template_buffer) + strlen(component_buffer) + (strlen(template_buffer) - (substring.end - template_buffer + strlen(COMPONENT_DELIMITER_END) + 1))] = '\0';

  return combined_buffer;
}

char* include_components_recursive_helper(char *template_path) {
  char *template_buffer = NULL;
  char *component_buffer = NULL;
  char *combined_buffer = NULL;

  char *component_path = NULL;

  template_buffer = file_into_buffer(template_path);

  printf("%s -- %s -- %s", template_path, template_buffer, template_path);

  component_path = get_component_path(template_buffer, dirname(template_path));

  while (component_path != NULL) {
    component_buffer = include_components_recursive_helper(component_path);

    combined_buffer = include_component(template_buffer, component_buffer);

    free(template_buffer);

    template_buffer = calloc(strlen(combined_buffer) + 1, sizeof(char));
    strcpy(template_buffer, combined_buffer);

    free(component_buffer);
    free(combined_buffer);
    free(component_path);

    component_path = get_component_path(combined_buffer, dirname(template_path));
  }

  free(component_path);

  return template_buffer;
}

char* include_components_recursively(char *root_template_path, char *html_path) {
  char root_template_realpath[PATH_MAX];
  char *root_template_path_dir = NULL;
  char *final_html = NULL;

  get_realpath(root_template_path, root_template_realpath);
  root_template_path_dir = dirname(root_template_realpath);

  final_html = include_components_recursive_helper(root_template_realpath);

  return final_html;
}

void write_to_file(char *file_path, char *buffer) {
  FILE *f;

  f = fopen(file_path, "w");
  fprintf(f, "%s", buffer);
  fclose(f);
}

int main(int argc, char *argv[]) {
  if (argc != 3) { usage(); }

  char *template_path = argv[1];
  char *html_path = argv[2];

  char *final_html_buffer = NULL;

  final_html_buffer = include_components_recursively(template_path, html_path);
  
  write_to_file(html_path, final_html_buffer);

  free(final_html_buffer);
}
