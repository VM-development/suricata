/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for AppLayerProtoDetectGetProto
 */


#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "stream-tcp-private.h"
#include "app-layer-parser.h"


#define HEADER_LEN 6


int g_detect_disabled = 0;
int g_disable_randomness = 1;
intmax_t max_pending_packets = 1;
int run_mode = RUNMODE_UNITTEST;
volatile uint8_t suricata_ctl_flags = 0;
int g_ut_covered;
int g_ut_modules;
int coverage_unittests;

SC_ATOMIC_DECLARE(unsigned int, engine_stage);

void EngineDone(void)
{
}

void EngineStop(void)
{
}

int EngineModeIsIPS(void)
{
    return 0;
}

void PostRunDeinit(const int runmode, struct timeval *start_time)
{
}

void PreRunInit(const int runmode)
{
}

void PreRunPostPrivsDropInit(const int runmode)
{
}

int RunmodeGetCurrent(void)
{
    return RUNMODE_UNITTEST;
}

int RunmodeIsUnittests(void)
{
    return 1;
}

int SuriHasSigFile(void)
{
    return 0;
}

void fuzz_openFile(const char * name) {
}

AppLayerParserThreadCtx *alp_tctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Flow * f;
    TcpSession ssn;

    if (Size < HEADER_LEN) {
        return 0;
    }

    if (alp_tctx == NULL) {
        //global init
        MpmTableSetup();
        SpmTableSetup();
        AppLayerProtoDetectSetup();
        AppLayerParserSetup();
        AppLayerParserRegisterProtocolParsers();
        alp_tctx = AppLayerParserThreadCtxAlloc();
#ifdef HAVE_RUST
        SuricataContext context;
        context.SCLogMessage = SCLogMessage;
        context.DetectEngineStateFree = DetectEngineStateFree;
        context.AppLayerDecoderEventsSetEventRaw =
        AppLayerDecoderEventsSetEventRaw;
        context.AppLayerDecoderEventsFreeEvents = AppLayerDecoderEventsFreeEvents;

        context.FileOpenFileWithId = FileOpenFileWithId;
        context.FileCloseFileById = FileCloseFileById;
        context.FileAppendDataById = FileAppendDataById;
        context.FileAppendGAPById = FileAppendGAPById;
        context.FileContainerRecycle = FileContainerRecycle;
        context.FilePrune = FilePrune;
        context.FileSetTx = FileContainerSetTx;

        rs_init(&context);
#endif
        SCLogInitLogModule(NULL);
        (void)SCSetThreadName("Suricata-Main");
        ConfInit();
        FlowInitConfig(FLOW_QUIET);
    }

    if (Data[0] >= ALPROTO_MAX) {
        return 0;
    }
    f = FlowAlloc();
    f->flags |= FLOW_IPV4;
    f->src.addr_data32[0] = 0x01020304;
    f->dst.addr_data32[0] = 0x05060708;
    f->sp = (Data[2] << 8) | Data[3];
    f->dp = (Data[4] << 8) | Data[5];
    f->proto = Data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);
    f->alproto = Data[0];

    int start = 1;
    int flip = 0;
    size_t offset = HEADER_LEN;
    while (1) {
        int done = 0;
        uint8_t flags = 0;
        size_t onesize = 0;
        if (flip) {
            flags = STREAM_TOCLIENT;
            flip = 0;
        } else {
            flags = STREAM_TOSERVER;
            flip = 1;
        }
        if (start > 0) {
            flags |= STREAM_START;
            start = 0;
        }
        if (Size < offset + 2) {
            onesize = 0;
            done = 1;
        } else {
            onesize = ((Data[offset]) << 8) | (Data[offset+1]);
            offset += 2;
            if (Size < offset + onesize) {
                onesize = Size - offset;
                done = 1;
            }
        }
        if (done) {
            flags |= STREAM_EOF;
        }

        (void) AppLayerParserParse(NULL, alp_tctx, f, f->alproto, flags, Data+offset, onesize);
        offset += onesize;
        if (done)
            break;

    }

    FlowFree(f);

    return 0;
}
