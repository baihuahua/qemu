/*
 *  Copyright 2016  Red Hat, Inc.
 *
 *  TCMU Handler Program
 *
 *  Authors:
 *    Fam Zheng <famz@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qemu/cutils.h"
#include "sysemu/block-backend.h"
#include "block/block_int.h"
#include "qemu/main-loop.h"
#include "qemu/error-report.h"
#include "qemu/config-file.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/option.h"
#include "block/snapshot.h"
#include "qapi/util.h"
#include "qapi/qmp/qstring.h"
#include "qom/object_interfaces.h"
#include "crypto/init.h"
#include "trace/control.h"
#include "scsi/tcmu.h"
#include <getopt.h>
#include "qemu-version.h"

#define QEMU_TCMU_OPT_CACHE         256
#define QEMU_TCMU_OPT_AIO           257
#define QEMU_TCMU_OPT_DISCARD       258
#define QEMU_TCMU_OPT_DETECT_ZEROES 259
#define QEMU_TCMU_OPT_OBJECT        260
#define QEMU_TCMU_OPT_IMAGE_OPTS    261
#define QEMU_TCMU_OPT_EXPORT	    262

static TCMUExport *exp;
static int verbose;
static char *srcpath;

static void usage(const char *name)
{
    (printf) (
"Usage: %s [OPTIONS] FILE\n"
"QEMU TCMU Handler\n"
"\n"
"  -h, --help                display this help and exit\n"
"  -V, --version             output version information and exit\n"
"\n"
"General purpose options:\n"
"  -v, --verbose             display extra debugging information\n"
"  -x, --handler-name=NAME   handler name to be used as the subtype for TCMU\n"
"  --object type,id=ID,...   define an object such as 'secret' for providing\n"
"                            passwords and/or encryption keys\n"
"  -T, --trace [[enable=]<pattern>][,events=<file>][,file=<file>]\n"
"                            specify tracing options\n"
"\n"
"Block device options:\n"
"  -f, --format=FORMAT       set image format (raw, qcow2, ...)\n"
"  -r, --read-only           export read-only\n"
"  -s, --snapshot            use FILE as an external snapshot, create a temporary\n"
"                            file with backing_file=FILE, redirect the write to\n"
"                            the temporary one\n"
"  -l, --load-snapshot=SNAPSHOT_PARAM\n"
"                            load an internal snapshot inside FILE and export it\n"
"                            as an read-only device, SNAPSHOT_PARAM format is\n"
"                            'snapshot.id=[ID],snapshot.name=[NAME]', or\n"
"                            '[ID_OR_NAME]'\n"
"  -n, --nocache             disable host cache\n"
"      --cache=MODE          set cache mode (none, writeback, ...)\n"
"      --aio=MODE            set AIO mode (native or threads)\n"
"      --discard=MODE        set discard mode (ignore, unmap)\n"
"      --detect-zeroes=MODE  set detect-zeroes mode (off, on, unmap)\n"
"      --image-opts          treat FILE as a full set of image options\n"
"\n"
"Report bugs to <qemu-devel@nongnu.org>\n"
    , name);
}

static void version(const char *name)
{
    printf("%s v" QEMU_VERSION QEMU_PKGVERSION "\n", name);
}

static enum { RUNNING, TERMINATE, TERMINATING, TERMINATED } state;

static QemuOptsList file_opts = {
    .name = "file",
    .implied_opt_name = "file",
    .head = QTAILQ_HEAD_INITIALIZER(file_opts.head),
    .desc = {
        /* no elements => accept any params */
        { /* end of list */ }
    },
};

static QemuOptsList qemu_object_opts = {
    .name = "object",
    .implied_opt_name = "qom-type",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_object_opts.head),
    .desc = {
        { }
    },
};

QemuOptsList qemu_tcmu_common_export_opts = {
    .name = "export",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_tcmu_common_export_opts.head),
    .desc = {
        {
            .name = "snapshot",
            .type = QEMU_OPT_BOOL,
            .help = "enable/disable snapshot mode",
        },{
            .name = "aio",
            .type = QEMU_OPT_STRING,
            .help = "host AIO implementation (threads, native)",
        },{
            .name = "format",
            .type = QEMU_OPT_STRING,
            .help = "disk format (raw, qcow2, ...)",
        },{
            .name = "file",
            .type = QEMU_OPT_STRING,
            .help = "file name",
        },
        { /* end of list */ }
    },
};

QemuOptsList qemu_tcmu_export_opts = {
    .name = "export",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_tcmu_export_opts.head),
    .desc = {
        /* no elements => accept any params */
        { /* end of list */ }
    },
};

static int export_init_func(void *opaque, QemuOpts *all_opts, Error **errp)
{
    int flags = BDRV_O_RDWR;
    const char *buf;
    int ret = 0;
    bool writethrough;
    BlockBackend *blk;
    //BlockDriverState *bs;
    int snapshot = 0;
    Error *local_err = NULL;
    QemuOpts *common_opts; 
    const char *id;
    const char *aio;
    const char *value;
    QDict *bs_opts;
    bool read_only = false;
    const char *file;
    TCMUExport *exp;

    value = qemu_opt_get(all_opts, "cache");
    if (value) {
        if (bdrv_parse_cache_mode(value, &flags, &writethrough) != 0) {
            error_report("invalid cache option");
            ret = -1;
	    goto err_too_early;
        }
        /* Specific options take precedence */
        if (!qemu_opt_get(all_opts, BDRV_OPT_CACHE_WB)) {
            qemu_opt_set_bool(all_opts, BDRV_OPT_CACHE_WB,
                              !writethrough, &error_abort);
        }
        if (!qemu_opt_get(all_opts, BDRV_OPT_CACHE_DIRECT)) {
            qemu_opt_set_bool(all_opts, BDRV_OPT_CACHE_DIRECT,
                              !!(flags & BDRV_O_NOCACHE), &error_abort);
        }
        if (!qemu_opt_get(all_opts, BDRV_OPT_CACHE_NO_FLUSH)) {
            qemu_opt_set_bool(all_opts, BDRV_OPT_CACHE_NO_FLUSH,
                              !!(flags & BDRV_O_NO_FLUSH), &error_abort);
        }
        qemu_opt_unset(all_opts, "cache");
    }

    bs_opts = qdict_new();
    qemu_opts_to_qdict(all_opts, bs_opts);

    id = qdict_get_try_str(bs_opts, "id");
    common_opts = qemu_opts_create(&qemu_tcmu_common_export_opts, id, 1,
                                   &local_err);
    if (local_err) {
        error_report_err(local_err);
        ret = -1;
        goto err_no_opts;
    }

    qemu_opts_absorb_qdict(common_opts, bs_opts, &local_err);
    if (local_err) {
        error_report_err(local_err);
	ret = -1;
        goto early_err;
    }

    if (id) {
        qdict_del(bs_opts, "id");
    }

    if ((aio = qemu_opt_get(common_opts, "aio")) != NULL) {
            if (!strcmp(aio, "native")) {
                flags |= BDRV_O_NATIVE_AIO;
            } else if (!strcmp(aio, "threads")) {
                /* this is the default */
            } else {
               error_report("invalid aio option");
	       ret = -1;
               goto early_err;
            }
    }

    if ((buf = qemu_opt_get(common_opts, "format")) != NULL) {
      /*  if (is_help_option(buf)) {
            error_printf("Supported formats:");
            bdrv_iterate_format(bdrv_format_print, NULL);
            error_printf("\n");
	    ret =-1;
            goto early_err;
        }*/

        if (qdict_haskey(bs_opts, "driver")) {
            error_report("Cannot specify both 'driver' and 'format'");
	    ret = -1;
            goto early_err;
        }
        qdict_put_str(bs_opts, "driver", buf);
    }

    snapshot = qemu_opt_get_bool(common_opts, "snapshot", 0);
    if (snapshot) {
        flags |= BDRV_O_SNAPSHOT;
    }

    read_only = qemu_opt_get_bool(common_opts, BDRV_OPT_READ_ONLY, false);
    if (read_only)
	flags &= ~BDRV_O_RDWR;

    /* bdrv_open() defaults to the values in bdrv_flags (for compatibility
     * with other callers) rather than what we want as the real defaults
     * Apply the defaults here instead. */
    qdict_set_default_str(bs_opts, BDRV_OPT_CACHE_DIRECT, "off");
    qdict_set_default_str(bs_opts, BDRV_OPT_CACHE_NO_FLUSH, "off");
    qdict_set_default_str(bs_opts, BDRV_OPT_READ_ONLY,
                              read_only ? "on" : "off");

    file = qemu_opt_get(common_opts, "file");
    blk = blk_new_open(file, NULL, bs_opts, flags, &local_err);
    if (!blk) {
        error_report_err(local_err);
	ret = -1;
        goto err_no_bs_opts;
    }
   // bs = blk_bs(blk);

    blk_set_enable_write_cache(blk, !writethrough);

    id = qemu_opts_id(common_opts);
    if (!monitor_add_blk(blk, id, &local_err)) {
        error_report_err(local_err);
        blk_unref(blk);
        ret = -1;
	goto err_no_bs_opts;
    }

    exp = qemu_tcmu_export(blk, flags & BDRV_O_RDWR, &local_err);
    if (!exp) {
        error_reportf_err(local_err, "Failed to create export: ");
        ret = -1;
    }

err_no_bs_opts:
    qemu_opts_del(common_opts);
    return ret;

early_err:
    qemu_opts_del(common_opts);
err_no_opts:
    QDECREF(bs_opts);
err_too_early:
    return ret;
}

int main(int argc, char **argv)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    QemuOpts *sn_opts = NULL;
    const char *sn_id_or_name = NULL;
    const char *sopt = "hVb:o:p:rsnP:c:dvk:e:f:tl:x:T:";
    bool starting = true;
    struct option lopt[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "read-only", no_argument, NULL, 'r' },
        { "snapshot", no_argument, NULL, 's' },
        { "load-snapshot", required_argument, NULL, 'l' },
        { "nocache", no_argument, NULL, 'n' },
        { "cache", required_argument, NULL, QEMU_TCMU_OPT_CACHE },
        { "aio", required_argument, NULL, QEMU_TCMU_OPT_AIO },
        { "discard", required_argument, NULL, QEMU_TCMU_OPT_DISCARD },
        { "detect-zeroes", required_argument, NULL,
          QEMU_TCMU_OPT_DETECT_ZEROES },
        { "shared", required_argument, NULL, 'e' },
        { "format", required_argument, NULL, 'f' },
        { "verbose", no_argument, NULL, 'v' },
        { "object", required_argument, NULL, QEMU_TCMU_OPT_OBJECT },
        { "handler-name", required_argument, NULL, 'x' },
        { "image-opts", no_argument, NULL, QEMU_TCMU_OPT_IMAGE_OPTS },
        { "trace", required_argument, NULL, 'T' },
        { "export", required_argument, NULL, QEMU_TCMU_OPT_EXPORT },
        { NULL, 0, NULL, 0 }
    };
    int ch;
    int opt_ind = 0;
    int flags = BDRV_O_RDWR;
    int ret = 0;
    bool seen_cache = false;
    bool seen_discard = false;
    bool seen_aio = false;
    const char *fmt = NULL;
    Error *local_err = NULL;
    BlockdevDetectZeroesOptions detect_zeroes = BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF;
    QDict *options = NULL;
    bool imageOpts = false;
    bool writethrough = true;
    char *trace_file = NULL;
    const char *subtype = "qemu";

    module_call_init(MODULE_INIT_TRACE);
    qcrypto_init(&error_fatal);

    module_call_init(MODULE_INIT_QOM);
    qemu_add_opts(&qemu_object_opts);
    qemu_add_opts(&qemu_trace_opts);
    qemu_init_exec_dir(argv[0]);

    while ((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
        switch (ch) {
        case 's':
            flags |= BDRV_O_SNAPSHOT;
            break;
        case 'n':
            optarg = (char *) "none";
            /* fallthrough */
        case QEMU_TCMU_OPT_CACHE:
            if (seen_cache) {
                error_report("-n and --cache can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_cache = true;
            if (bdrv_parse_cache_mode(optarg, &flags, &writethrough) == -1) {
                error_report("Invalid cache mode `%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case QEMU_TCMU_OPT_AIO:
            if (seen_aio) {
                error_report("--aio can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_aio = true;
            if (!strcmp(optarg, "native")) {
                flags |= BDRV_O_NATIVE_AIO;
            } else if (!strcmp(optarg, "threads")) {
                /* this is the default */
            } else {
               error_report("invalid aio mode `%s'", optarg);
               exit(EXIT_FAILURE);
            }
            break;
        case QEMU_TCMU_OPT_DISCARD:
            if (seen_discard) {
                error_report("--discard can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_discard = true;
            if (bdrv_parse_discard_flags(optarg, &flags) == -1) {
                error_report("Invalid discard mode `%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case QEMU_TCMU_OPT_DETECT_ZEROES:
            detect_zeroes =
                qapi_enum_parse(BlockdevDetectZeroesOptions_lookup,
                                optarg,
                                BLOCKDEV_DETECT_ZEROES_OPTIONS__MAX,
                                BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF,
                                &local_err);
            if (local_err) {
                error_reportf_err(local_err,
                                  "Failed to parse detect_zeroes mode: ");
                exit(EXIT_FAILURE);
            }
            if (detect_zeroes == BLOCKDEV_DETECT_ZEROES_OPTIONS_UNMAP &&
                !(flags & BDRV_O_UNMAP)) {
                error_report("setting detect-zeroes to unmap is not allowed "
                             "without setting discard operation to unmap");
                exit(EXIT_FAILURE);
            }
            break;
        case 'l':
            if (strstart(optarg, SNAPSHOT_OPT_BASE, NULL)) {
                sn_opts = qemu_opts_parse_noisily(&internal_snapshot_opts,
                                                  optarg, false);
                if (!sn_opts) {
                    error_report("Failed in parsing snapshot param `%s'",
                                 optarg);
                    exit(EXIT_FAILURE);
                }
            } else {
                sn_id_or_name = optarg;
            }
            /* fall through */
        case 'r':
            flags &= ~BDRV_O_RDWR;
            break;
        case 'f':
            fmt = optarg;
            break;
        case 'x':
            subtype = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'V':
            version(argv[0]);
            exit(0);
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
            break;
        case '?':
            error_report("Try `%s --help' for more information.", argv[0]);
            exit(EXIT_FAILURE);
        case QEMU_TCMU_OPT_OBJECT: {
            QemuOpts *opts;
            opts = qemu_opts_parse_noisily(&qemu_object_opts,
                                           optarg, true);
            if (!opts) {
                exit(EXIT_FAILURE);
            }
        }   break;
        case QEMU_TCMU_OPT_IMAGE_OPTS:
            imageOpts = true;
            break;
        case 'T':
            g_free(trace_file);
            trace_file = trace_opt_parse(optarg);
            break;
	case QEMU_TCMU_OPT_EXPORT: {
	    QemuOpts *tcmu_opts;
	    tcmu_opts = qemu_opts_parse_noisily(&qemu_tcmu_export_opts,
						optarg, false);
	    if (!tcmu_opts) {
                exit(EXIT_FAILURE);
            }
	}    break;
        }
    }

    if ((argc - optind) != 1) {
        error_report("Invalid number of arguments");
        error_printf("Try `%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (qemu_opts_foreach(&qemu_object_opts,
                          user_creatable_add_opts_foreach,
                          NULL, NULL)) {
        exit(EXIT_FAILURE);
    }

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);
    qemu_set_log(LOG_TRACE);

    if (qemu_init_main_loop(&local_err)) {
        error_report_err(local_err);
        exit(EXIT_FAILURE);
    }
    bdrv_init();
    atexit(bdrv_close_all);

    if (qemu_opts_foreach(&qemu_tcmu_export_opts, export_init_func,
			  NULL, NULL))
	exit(0);

    srcpath = argv[optind];
    if (imageOpts) {
        QemuOpts *opts;
        if (fmt) {
            error_report("--image-opts and -f are mutually exclusive");
            exit(EXIT_FAILURE);
        }
        opts = qemu_opts_parse_noisily(&file_opts, srcpath, true);
        if (!opts) {
            qemu_opts_reset(&file_opts);
            exit(EXIT_FAILURE);
        }
        options = qemu_opts_to_qdict(opts, NULL);
        qemu_opts_reset(&file_opts);
        blk = blk_new_open(NULL, NULL, options, flags, &local_err);
    } else {
        if (fmt) {
            options = qdict_new();
            qdict_put(options, "driver", qstring_from_str(fmt));
        }
        blk = blk_new_open(srcpath, NULL, options, flags, &local_err);
    }

    if (!blk) {
        error_reportf_err(local_err, "Failed to blk_new_open '%s': ",
                          argv[optind]);
        exit(EXIT_FAILURE);
    }
    monitor_add_blk(blk, "drive", &error_fatal);
    bs = blk_bs(blk);

    blk_set_enable_write_cache(blk, !writethrough);

    if (sn_opts) {
        ret = bdrv_snapshot_load_tmp(bs,
                                     qemu_opt_get(sn_opts, SNAPSHOT_OPT_ID),
                                     qemu_opt_get(sn_opts, SNAPSHOT_OPT_NAME),
                                     &local_err);
    } else if (sn_id_or_name) {
        ret = bdrv_snapshot_load_tmp_by_id_or_name(bs, sn_id_or_name,
                                                   &local_err);
    }
    if (ret < 0) {
        error_reportf_err(local_err, "Failed to load snapshot: ");
        exit(EXIT_FAILURE);
    }

    bs->detect_zeroes = detect_zeroes;
    exp = qemu_tcmu_export(blk, flags & BDRV_O_RDWR, &local_err);
    if (!exp) {
        error_reportf_err(local_err, "Failed to create export: ");
        exit(EXIT_FAILURE);
    }

    /* now when the initialization is (almost) complete, chdir("/")
     * to free any busy filesystems */
    if (chdir("/") < 0) {
        error_report("Could not chdir to root directory: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }

    state = RUNNING;
    do {
        g_main_context_acquire(g_main_context_default());
        main_loop_wait(starting);
        g_main_context_release(g_main_context_default());
        if (starting) {
            qemu_tcmu_start(subtype, &local_err);
            if (local_err) {
                error_report_err(local_err);
                exit(EXIT_FAILURE);
            }
            starting = false;
        }
        if (state == TERMINATE) {
            state = TERMINATING;
            exp = NULL;
        }
    } while (state != TERMINATED);

    blk_unref(blk);

    qemu_opts_del(sn_opts);

    exit(EXIT_SUCCESS);
}
