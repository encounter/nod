#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SDL3/SDL.h>

#include "nod.h"

typedef struct SDLStreamCtx {
  SDL_IOStream *io;
} SDLStreamCtx;

static int64_t sdl_stream_read_at(void *user_data, uint64_t offset, void *out,
                                  size_t len) {
  SDLStreamCtx *ctx = (SDLStreamCtx *)user_data;
  if (ctx == NULL || ctx->io == NULL || offset > (uint64_t)INT64_MAX) {
    return -1;
  }

  if (SDL_SeekIO(ctx->io, (Sint64)offset, SDL_IO_SEEK_SET) < 0) {
    return -1;
  }

  size_t total = 0;
  Uint8 *dst = (Uint8 *)out;
  while (total < len) {
    size_t n = SDL_ReadIO(ctx->io, dst + total, len - total);
    if (n == 0) {
      break;
    }
    total += n;
  }
  return (int64_t)total;
}

static int64_t sdl_stream_len(void *user_data) {
  SDLStreamCtx *ctx = (SDLStreamCtx *)user_data;
  if (ctx == NULL || ctx->io == NULL) {
    return -1;
  }
  return (int64_t)SDL_GetIOSize(ctx->io);
}

static void sdl_stream_close(void *user_data) {
  SDLStreamCtx *ctx = (SDLStreamCtx *)user_data;
  if (ctx == NULL) {
    return;
  }
  if (ctx->io != NULL) {
    SDL_CloseIO(ctx->io);
  }
  SDL_free(ctx);
}

static void print_nod_error(const char *context) {
  const char *msg = nod_error_message();
  fprintf(stderr, "%s: %s\n", context, msg ? msg : "(no error message)");
}

typedef struct ListCtx {
  uint32_t printed;
  uint32_t max_print;
  NodHandle *partition;
} ListCtx;

static void print_file_preview(NodHandle *partition, uint32_t fst_index,
                               uint32_t file_size) {
  if (partition == NULL) {
    return;
  }
  if (file_size == 0) {
    printf("        data: <empty>\n");
    return;
  }

  NodHandle *file = NULL;
  NodResult result = nod_partition_open_file(partition, fst_index, &file);
  if (result != NOD_RESULT_OK) {
    print_nod_error("nod_partition_open_file failed");
    return;
  }

  // `nod_buf_read` provides zero-copy access to internal buffers for efficient reading.
  // On success, it returns a pointer to the data and sets `avail` to the number of bytes available.
  // Afterwards, one must call `nod_buf_consume` to advance the internal buffer by the number of bytes used.
  size_t avail = 0;
  const uint8_t *chunk = (const uint8_t *)nod_buf_read(file, &avail);
  size_t take = (avail < 16) ? avail : 16;

  printf("        data:");
  for (size_t i = 0; i < take; ++i) {
    printf(" %02X", chunk[i]);
  }
  if (take < (size_t)file_size) {
    printf(" ...");
  }
  printf("\n");

  // Once we're done with the data from `nod_buf_read`, we need to call
  // `nod_buf_consume` to advance the internal buffer.
  // (Since we're freeing it immediately after, this isn't strictly necessary
  // in this example, but it's here to demonstrate proper usage.)
  nod_buf_consume(file, take);

  nod_free(file);
}

static uint32_t list_fst_entry(uint32_t index, enum NodNodeKind kind,
                               const char *name, uint32_t size,
                               void *user_data) {
  ListCtx *ctx = (ListCtx *)user_data;
  const char *kind_name = (kind == NOD_NODE_KIND_DIRECTORY) ? "dir" : "file";

  printf("[%5" PRIu32 "] %-4s %10" PRIu32 "  %s\n", index, kind_name, size,
         name ? name : "");
  if (kind == NOD_NODE_KIND_FILE) {
    print_file_preview(ctx->partition, index, size);
  }

  ctx->printed += 1;
  if (ctx->printed >= ctx->max_print) {
    return NOD_FST_STOP;
  }
  return index + 1;
}

static void print_usage(const char *prog) {
  const char *name =
      (prog != NULL && prog[0] != '\0') ? prog : "nod_sdl3_stream_demo";
  fprintf(stderr, "Usage: %s <disc-image-path>\n", name);
  fprintf(stderr, "\n");
  fprintf(stderr,
          "Opens a GameCube/Wii disc image via SDL_IOStream and nod-ffi.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -h, --help    Show this help text\n");
}

int main(int argc, char **argv) {
  if (argc == 2 &&
      (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    print_usage(argv[0]);
    return 0;
  }

  if (argc != 2) {
    print_usage(argv[0]);
    return 1;
  }

  const char *path = argv[1];

  if (!SDL_Init(0)) {
    fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
    return 1;
  }

  SDL_IOStream *io = SDL_IOFromFile(path, "rb");
  if (io == NULL) {
    fprintf(stderr, "SDL_IOFromFile failed for '%s': %s\n", path,
            SDL_GetError());
    SDL_Quit();
    return 1;
  }

  SDLStreamCtx *ctx = (SDLStreamCtx *)SDL_malloc(sizeof(*ctx));
  if (ctx == NULL) {
    fprintf(stderr, "SDL_malloc failed\n");
    SDL_CloseIO(io);
    SDL_Quit();
    return 1;
  }
  ctx->io = io;

  NodHandle *disc = NULL;
  NodResult result = nod_disc_open_stream(
      &(NodDiscStream){
          .user_data = ctx,
          .read_at = sdl_stream_read_at,
          .stream_len = sdl_stream_len,
          .close = sdl_stream_close,
      },
      &(NodDiscOptions){
          // Enable 1 thread for preloading data in the background while reading
          // the disc. When using the FFI stream API, reads are synchronized, so
          // more than 1 thread is not beneficial.
          .preloader_threads = 1,
      },
      &disc);
  if (result != NOD_RESULT_OK) {
    print_nod_error("nod_disc_open_stream failed");
    SDL_Quit();
    return 1;
  }

  NodDiscHeader header = {0};
  result = nod_disc_header(disc, &header);
  if (result != NOD_RESULT_OK) {
    print_nod_error("nod_disc_header failed");
    nod_free(disc);
    SDL_Quit();
    return 1;
  }

  NodDiscMeta meta = {0};
  result = nod_disc_meta(disc, &meta);
  if (result != NOD_RESULT_OK) {
    print_nod_error("nod_disc_meta failed");
    nod_free(disc);
    SDL_Quit();
    return 1;
  }

  printf("Opened: %s\n", path);

  // Copy the game ID and title into null-terminated buffers for printing.
  char game_id[sizeof(header.game_id) + 1];
  memcpy(game_id, header.game_id, sizeof(header.game_id));
  game_id[sizeof(header.game_id)] = '\0';

  char game_title[sizeof(header.game_title) + 1];
  memcpy(game_title, header.game_title, sizeof(header.game_title));
  game_title[sizeof(header.game_title)] = '\0';

  // Determine disc type based on magic bytes in the header.
  bool is_wii = NOD_MAGIC_EQ(header.wii_magic, WII_MAGIC);
  bool is_gamecube = NOD_MAGIC_EQ(header.gcn_magic, GCN_MAGIC);
  const char *disc_type = is_wii ? "Wii" : (is_gamecube ? "GameCube" : "Unknown");

  printf("Game ID: %s\n", game_id);
  printf("Title  : %s\n", game_title);
  printf("Type   : %s\n", disc_type);
  printf("Disc   : %u, rev %u\n", header.disc_num, header.disc_version);
  printf("Size   : %" PRIu64 " bytes\n", meta.disc_size);
  printf("\n");

  NodHandle *partition = NULL;
  result = nod_disc_open_partition_kind(disc, NOD_PARTITION_KIND_DATA, NULL,
                                        &partition);
  if (result != NOD_RESULT_OK) {
    print_nod_error("nod_disc_open_partition_kind(data) failed");
    nod_free(disc);
    SDL_Quit();
    return 1;
  }

  ListCtx list_ctx = {.max_print = 20, .partition = partition};
  printf("First %d entries in data partition FST:\n", list_ctx.max_print);
  nod_partition_iterate_fst(partition, list_fst_entry, &list_ctx);

  nod_free(partition);
  nod_free(disc);
  SDL_Quit();
  return 0;
}
