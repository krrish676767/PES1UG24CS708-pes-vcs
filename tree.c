// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions: tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
// "<mode-as-ascii-octal> <n>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
// "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
extern int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE 0100644
#define MODE_EXEC 0100755
#define MODE_DIR  0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))   return MODE_DIR;
    if (st.st_mode & S_IXUSR)  return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';
        ptr = null_byte + 1;

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Max size: (6 bytes mode + 1 space + 256 name + 1 null + 32 hash) per entry
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Sort entries by name (required for deterministic hashing)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count,
          sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];

        // Write "<mode> <name>\0"
        int written = sprintf((char *)buffer + offset, "%o %s",
                              entry->mode, entry->name);
        offset += written + 1; // +1 for the '\0' written by sprintf

        // Write raw 32-byte hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out  = offset;
    return 0;
}

// ─── IMPLEMENTED: tree_from_index ────────────────────────────────────────────
//
// Recursively builds tree objects from the index entries and writes them
// all to the object store. Returns the root tree ObjectID in *id_out.

// Forward declaration of recursive helper
static int write_tree_level(IndexEntry *entries, int count,
                             const char *prefix, ObjectID *id_out);

// Helper: returns the component of 'path' after stripping 'prefix/'
// e.g. prefix="src", path="src/main.c" → returns "main.c"
// If path doesn't start with prefix, returns NULL.
static const char *strip_prefix(const char *path, const char *prefix) {
    if (!prefix || prefix[0] == '\0') return path;
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) == 0 && path[plen] == '/') {
        return path + plen + 1;
    }
    return NULL;
}

// Recursive helper that builds one level of the tree.
// 'entries' is the full index entry array, 'count' is its size.
// 'prefix' is the directory prefix for this level (empty string = root).
// Writes the tree object and stores its hash in *id_out.
static int write_tree_level(IndexEntry *entries, int count,
                             const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        // Get the path relative to our current prefix level
        const char *rel;
        if (prefix[0] == '\0') {
            rel = entries[i].path; // at root level
        } else {
            rel = strip_prefix(entries[i].path, prefix);
            if (!rel) { i++; continue; } // not in our subtree
        }

        // Check if this entry is directly in this directory (no '/' in rel)
        const char *slash = strchr(rel, '/');

        if (!slash) {
            // ── Direct file entry ──────────────────────────────────────────
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            strncpy(te->name, rel, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            i++;
        } else {
            // ── Subdirectory entry ─────────────────────────────────────────
            // Extract the subdirectory name (first component)
            char subdir_name[256];
            size_t subdir_len = slash - rel;
            if (subdir_len >= sizeof(subdir_name)) return -1;
            memcpy(subdir_name, rel, subdir_len);
            subdir_name[subdir_len] = '\0';

            // Build the full prefix for the recursive call
            char sub_prefix[1024];
            if (prefix[0] == '\0') {
                snprintf(sub_prefix, sizeof(sub_prefix), "%s", subdir_name);
            } else {
                snprintf(sub_prefix, sizeof(sub_prefix), "%s/%s",
                         prefix, subdir_name);
            }

            // Collect all entries that belong to this subdirectory
            // (skip duplicates — only recurse once per unique subdir name)
            // Check if we already added this subdir as a tree entry
            int already_added = 0;
            for (int k = 0; k < tree.count; k++) {
                if (strcmp(tree.entries[k].name, subdir_name) == 0) {
                    already_added = 1;
                    break;
                }
            }

            if (!already_added) {
                // Recursively build the subtree
                ObjectID sub_id;
                if (write_tree_level(entries, count, sub_prefix, &sub_id) != 0)
                    return -1;

                // Add the subtree as a directory entry
                if (tree.count >= MAX_TREE_ENTRIES) return -1;
                TreeEntry *te = &tree.entries[tree.count++];
                te->mode = MODE_DIR;
                te->hash = sub_id;
                strncpy(te->name, subdir_name, sizeof(te->name) - 1);
                te->name[sizeof(te->name) - 1] = '\0';
            }
            i++;
        }
    }

    // Serialize this tree level and write it to the object store
    void *tree_data = NULL;
    size_t tree_len = 0;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) return -1;

    int ret = object_write(OBJ_TREE, tree_data, tree_len, id_out);
    free(tree_data);
    return ret;
}

// Public entry point: builds the full tree from the current index.
int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) return -1;

    if (index.count == 0) {
        // Empty index — write an empty tree
        Tree empty_tree;
        empty_tree.count = 0;
        void *tree_data = NULL;
        size_t tree_len = 0;
        if (tree_serialize(&empty_tree, &tree_data, &tree_len) != 0) return -1;
        int ret = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return ret;
    }

    // Sort index entries by path for consistent processing
    // (simple bubble sort — index is small)
    for (int i = 0; i < index.count - 1; i++) {
        for (int j = i + 1; j < index.count; j++) {
            if (strcmp(index.entries[i].path, index.entries[j].path) > 0) {
                IndexEntry tmp = index.entries[i];
                index.entries[i] = index.entries[j];
                index.entries[j] = tmp;
            }
        }
    }

    // Build tree from root level (empty prefix)
    return write_tree_level(index.entries, index.count, "", id_out);
}

// Weak stub — only used by test_tree which doesn't link index.o.
// The real index_load in index.c takes precedence in the full pes binary.
__attribute__((weak)) int index_load(Index *index) {
    index->count = 0;
    return 0;
}
// Phase 2 complete
