#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HEADER_LIMIT 64
#define PDF_SEARCH_LIMIT 1024
#define TAIL_SEARCH_LIMIT 1024
#define PNG_HEADER_SIZE 33

static int extension_equals(const char *path, const char *extension) {
    const char *dot = strrchr(path, '.');
    size_t index;

    if (dot == NULL) {
        return 0;
    }

    for (index = 0; extension[index] != '\0'; index++) {
        if (dot[index] == '\0' ||
            tolower((unsigned char)dot[index]) !=
                tolower((unsigned char)extension[index])) {
            return 0;
        }
    }

    return dot[index] == '\0';
}

static int seek_to(FILE *file, long offset) {
    return offset >= 0 && fseek(file, offset, SEEK_SET) == 0;
}

static size_t read_at(FILE *file, long offset, unsigned char *buffer,
                      size_t length) {
    if (!seek_to(file, offset)) {
        return 0;
    }
    return fread(buffer, 1, length, file);
}

static void print_hex(const unsigned char *data, size_t length) {
    size_t index;
    for (index = 0; index < length; index++) {
        printf("%02x", data[index]);
    }
}

static uint32_t read_u32_be(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint32_t crc32_bytes(const unsigned char *data, size_t length) {
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    int bit;

    for (index = 0; index < length; index++) {
        crc ^= data[index];
        for (bit = 0; bit < 8; bit++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static void analyze_pdf(FILE *file, long file_size,
                        const unsigned char *header, size_t header_length) {
    unsigned char search[PDF_SEARCH_LIMIT];
    unsigned char tail[TAIL_SEARCH_LIMIT];
    size_t search_length = (size_t)file_size;
    size_t tail_length = (size_t)file_size;
    size_t index;
    long header_offset = -1;
    int version_valid = 0;
    int signature_at_start;
    int eof_present = 0;
    int checks_complete;

    if (search_length > sizeof(search)) {
        search_length = sizeof(search);
    }
    if (tail_length > sizeof(tail)) {
        tail_length = sizeof(tail);
    }

    checks_complete =
        read_at(file, 0, search, search_length) == search_length &&
        read_at(file, file_size - (long)tail_length, tail, tail_length) ==
            tail_length;

    if (checks_complete) {
        for (index = 0; index + 5 <= search_length; index++) {
            if (memcmp(search + index, "%PDF-", 5) == 0) {
                header_offset = (long)index;
                version_valid =
                    index + 8 <= search_length &&
                    isdigit(search[index + 5]) &&
                    search[index + 6] == '.' &&
                    isdigit(search[index + 7]);
                break;
            }
        }

        for (index = 0; index + 5 <= tail_length; index++) {
            if (memcmp(tail + index, "%%EOF", 5) == 0) {
                eof_present = 1;
                break;
            }
        }
    }

    signature_at_start = header_offset == 0;
    printf("{\"format\":\"PDF\",\"file_size\":%ld,\"signature_offset\":",
           file_size);
    if (header_offset < 0) {
        printf("null");
    } else {
        printf("%ld", header_offset);
    }
    printf(",\"header_hex\":\"");
    print_hex(header, header_length);
    printf("\",\"header_valid\":%s,\"checks\":{"
           "\"pdf_signature_found\":%s,"
           "\"pdf_signature_at_start\":%s,"
           "\"pdf_version_valid\":%s,"
           "\"pdf_eof_marker_present\":%s},\"anomalies\":[",
           signature_at_start && version_valid ? "true" : "false",
           header_offset >= 0 ? "true" : "false",
           signature_at_start ? "true" : "false",
           version_valid ? "true" : "false", eof_present ? "true" : "false");

    if (!checks_complete) {
        printf("\"pdf_read_error\"");
    } else {
        int has_anomaly = 0;
        if (header_offset < 0) {
            printf("\"pdf_signature_missing\"");
            has_anomaly = 1;
        } else if (header_offset > 0) {
            printf("\"pdf_signature_not_at_start\"");
            has_anomaly = 1;
        }
        if (header_offset >= 0 && !version_valid) {
            printf("%s\"pdf_version_invalid\"", has_anomaly ? "," : "");
            has_anomaly = 1;
        }
        if (!eof_present) {
            printf("%s\"pdf_eof_marker_missing\"", has_anomaly ? "," : "");
        }
    }
    printf("]}\n");
}

static void analyze_png(FILE *file, long file_size,
                        const unsigned char *header, size_t header_length) {
    static const unsigned char signature[8] = {
        0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    unsigned char png_header[PNG_HEADER_SIZE];
    size_t bytes_read = read_at(file, 0, png_header, sizeof(png_header));
    int signature_valid = bytes_read >= 8 &&
                          memcmp(png_header, signature, sizeof(signature)) == 0;
    int ihdr_present = bytes_read >= 16 &&
                       memcmp(png_header + 12, "IHDR", 4) == 0;
    int ihdr_length_valid =
        bytes_read >= 12 && read_u32_be(png_header + 8) == 13;
    int dimensions_valid =
        bytes_read >= 24 && read_u32_be(png_header + 16) > 0 &&
        read_u32_be(png_header + 20) > 0;
    int crc_valid = bytes_read == PNG_HEADER_SIZE &&
                    crc32_bytes(png_header + 12, 17) ==
                        read_u32_be(png_header + 29);
    int header_valid = signature_valid && ihdr_present &&
                       ihdr_length_valid && dimensions_valid && crc_valid;
    int has_anomaly = 0;

    printf("{\"format\":\"PNG\",\"file_size\":%ld,\"signature_offset\":0,"
           "\"header_hex\":\"",
           file_size);
    print_hex(header, header_length);
    printf("\",\"header_valid\":%s,\"checks\":{"
           "\"png_signature_valid\":%s,"
           "\"png_ihdr_present\":%s,"
           "\"png_ihdr_length_valid\":%s,"
           "\"png_dimensions_valid\":%s,"
           "\"png_ihdr_crc_valid\":%s},\"anomalies\":[",
           header_valid ? "true" : "false",
           signature_valid ? "true" : "false", ihdr_present ? "true" : "false",
           ihdr_length_valid ? "true" : "false",
           dimensions_valid ? "true" : "false", crc_valid ? "true" : "false");

#define PRINT_PNG_ANOMALY(condition, name) \
    do {                                    \
        if (!(condition)) {                 \
            printf("%s\"%s\"", has_anomaly ? "," : "", name); \
            has_anomaly = 1;                \
        }                                   \
    } while (0)

    PRINT_PNG_ANOMALY(signature_valid, "png_signature_invalid");
    PRINT_PNG_ANOMALY(ihdr_present, "png_ihdr_missing");
    PRINT_PNG_ANOMALY(ihdr_length_valid, "png_ihdr_length_invalid");
    PRINT_PNG_ANOMALY(dimensions_valid, "png_dimensions_invalid");
    PRINT_PNG_ANOMALY(crc_valid, "png_ihdr_crc_invalid");
#undef PRINT_PNG_ANOMALY

    if (file_size < PNG_HEADER_SIZE && !has_anomaly) {
        printf("\"png_header_truncated\"");
    }
    printf("]}\n");
}

static void analyze_exe(FILE *file, long file_size,
                        const unsigned char *header, size_t header_length) {
    unsigned char pe_signature[4];
    uint32_t pe_offset = 0;
    int mz_valid = header_length >= 2 && header[0] == 'M' && header[1] == 'Z';
    int offset_read = header_length >= 64;
    int pe_offset_valid = 0;
    int pe_signature_valid = 0;
    int has_anomaly = 0;

    if (offset_read) {
        pe_offset = (uint32_t)header[0x3c] |
                    ((uint32_t)header[0x3d] << 8) |
                    ((uint32_t)header[0x3e] << 16) |
                    ((uint32_t)header[0x3f] << 24);
        pe_offset_valid = pe_offset <= (uint32_t)LONG_MAX &&
                          (uint64_t)pe_offset + sizeof(pe_signature) <=
                              (uint64_t)file_size;
        if (pe_offset_valid &&
            read_at(file, (long)pe_offset, pe_signature,
                    sizeof(pe_signature)) == sizeof(pe_signature)) {
            pe_signature_valid =
                memcmp(pe_signature, "PE\0\0", sizeof(pe_signature)) == 0;
        }
    }

    printf("{\"format\":\"EXE/PE\",\"file_size\":%ld,\"signature_offset\":",
           file_size);
    if (pe_offset_valid) {
        printf("%" PRIu32, pe_offset);
    } else {
        printf("null");
    }
    printf(",\"header_hex\":\"");
    print_hex(header, header_length);
    printf("\",\"header_valid\":%s,\"checks\":{"
           "\"dos_mz_signature_valid\":%s,"
           "\"pe_offset_available\":%s,"
           "\"pe_offset_in_file\":%s,"
           "\"pe_signature_valid\":%s},\"anomalies\":[",
           mz_valid && pe_offset_valid && pe_signature_valid ? "true" : "false",
           mz_valid ? "true" : "false", offset_read ? "true" : "false",
           pe_offset_valid ? "true" : "false",
           pe_signature_valid ? "true" : "false");

#define PRINT_EXE_ANOMALY(condition, name) \
    do {                                    \
        if (!(condition)) {                 \
            printf("%s\"%s\"", has_anomaly ? "," : "", name); \
            has_anomaly = 1;                \
        }                                   \
    } while (0)

    PRINT_EXE_ANOMALY(mz_valid, "dos_mz_signature_invalid");
    PRINT_EXE_ANOMALY(offset_read, "pe_offset_unavailable");
    PRINT_EXE_ANOMALY(pe_offset_valid, "pe_offset_out_of_file");
    PRINT_EXE_ANOMALY(pe_signature_valid, "pe_signature_missing");
#undef PRINT_EXE_ANOMALY

    printf("]}\n");
}

int main(int argc, char **argv) {
    FILE *file;
    long file_size;
    unsigned char header[HEADER_LIMIT];
    size_t header_length;
    int format_pdf;
    int format_png;
    int format_exe;

    if (argc != 2) {
        fprintf(stderr, "Uso: header_analyzer <archivo>\n");
        return 2;
    }

    format_pdf = extension_equals(argv[1], ".pdf");
    format_png = extension_equals(argv[1], ".png");
    format_exe = extension_equals(argv[1], ".exe");
    if (!format_pdf && !format_png && !format_exe) {
        fprintf(stderr, "Formato no soportado. Usa archivos PDF, PNG o EXE.\n");
        return 3;
    }

    file = fopen(argv[1], "rb");
    if (file == NULL) {
        fprintf(stderr, "No se pudo abrir el archivo.\n");
        return 4;
    }

    if (fseek(file, 0, SEEK_END) != 0 ||
        (file_size = ftell(file)) < 0 ||
        !seek_to(file, 0)) {
        fprintf(stderr, "No se pudo leer el tamaño del archivo.\n");
        fclose(file);
        return 4;
    }

    header_length = (size_t)file_size;
    if (header_length > sizeof(header)) {
        header_length = sizeof(header);
    }
    if (fread(header, 1, header_length, file) != header_length) {
        fprintf(stderr, "No se pudo leer la cabecera del archivo.\n");
        fclose(file);
        return 4;
    }

    if (format_pdf) {
        analyze_pdf(file, file_size, header, header_length);
    } else if (format_png) {
        analyze_png(file, file_size, header, header_length);
    } else {
        analyze_exe(file, file_size, header, header_length);
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "No se pudo cerrar el archivo.\n");
        return 4;
    }
    return 0;
}
