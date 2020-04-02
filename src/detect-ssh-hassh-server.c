/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Vadym Malakhatko <malahatkovadim@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "stream-tcp.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-hassh-server.h"
#include "rust.h"


#define KEYWORD_NAME "hasshServer"
#define KEYWORD_NAME_LEGACY "hasshServer"
#define KEYWORD_DOC "ssh-keywords.html#hasshServer"
#define BUFFER_NAME "hasshServer"
#define BUFFER_DESC "Ssh Client Fingerprinting For Ssh Servers"
static int g_ssh_hassh_buffer_id = 0;


static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *hasshServer = NULL;
        uint32_t b_len = 0;

        if (rs_ssh_tx_get_hassh_server(txv, &hasshServer, &b_len, flow_flags) != 1)
            return NULL;
        if (hasshServer == NULL || b_len == 0) {
            SCLogDebug("SSH hassh not set");
            return NULL;
        }

        InspectionBufferSetup(buffer, hasshServer, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief this function setup the hasshServer modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 * \retval -2 on failure that should be silent after the first
 */
static int DetectSshHasshServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_ssh_hassh_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;
            
    /* try to enable Hassh */
    SSHEnableHassh();

    /* Check if Hassh is disabled */
    if (!RunmodeIsUnittests() && !SSHHasshIsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_SSH_HASSH_SERVER)) {
            SCLogError(SC_WARN_HASSH_DISABLED, "hassh support is not enabled");
        }
        return -2;
    }

    return 0;

}


static _Bool DetectSshHasshServerHashValidateCallback(const Signature *s,
                                              const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_ssh_hassh_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "hasshServer should not be used together with "
                        "nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len == 32)
            return TRUE;

        *sigerror = "Invalid length of the specified hasshServer (should "
                    "be 32 characters long). This rule will therefore "
                    "never match.";
        SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
        return FALSE;
    }

    return TRUE;
}

static void DetectSshHasshServerHashSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_ssh_hassh_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (isupper(cd->content[u])) {
                cd->content[u] = tolower(cd->content[u]);
            }
        }

        SpmDestroyCtx(cd->spm_ctx);
        cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
        		de_ctx->spm_global_thread_ctx);
    }
}

#ifdef UNITTESTS
#include "tests/detect-ssh-hassh-server.c"
#endif

/**
 * \brief Registration function for hasshServer keyword.
 */
void DetectSshHasshServerRegister(void) 
{
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].desc = BUFFER_NAME " sticky buffer";
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].RegisterTests = DetectSshHasshServerRegisterTests;
#endif
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].Setup = DetectSshHasshServerSetup;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister, GetSshData, ALPROTO_SSH, SSH_STATE_BANNER_DONE),
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_SSH, SIG_FLAG_TOCLIENT, SSH_STATE_BANNER_DONE, DetectEngineInspectBufferGeneric, GetSshData);
    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ssh_hassh_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME, DetectSshHasshServerHashSetupCallback);
    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME, DetectSshHasshServerHashValidateCallback);
}
