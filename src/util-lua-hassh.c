/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssl.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-hassh.h"

static int HasshGet(lua_State *luastate)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    const uint8_t *hassh = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_hassh(state, &hassh, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no hassh");
    if (hassh == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no hassh");
    }

    return LuaPushStringBuffer(luastate, hassh, b_len);
}

static int HasshGetString(lua_State *luastate)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    const uint8_t *hassh_string = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_hassh_string(state, &hassh_string, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no hassh_string");
    if (hassh_string == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no hassh_string");
    }

    return LuaPushStringBuffer(luastate, hassh_string, b_len);
}

static int HasshServerGet(lua_State *luastate)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    const uint8_t *hassh_server = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_hassh_string(state, &hassh_server, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no hassh_server");
    if (hassh_server == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no hassh_server");
    }

    return LuaPushStringBuffer(luastate, hassh_server, b_len);
}

static int HasshServerGetString(lua_State *luastate)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    const uint8_t *hassh_server_string = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_hassh_string(state, &hassh_server_string, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no hassh_server_string");
    if (hassh_server_string == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no hassh_server_string");
    }

    return LuaPushStringBuffer(luastate, hassh_server_string, b_len);
}

/** *\brief Register Hassh Lua extensions */
int LuaRegisterHasshFunctions(lua_State *luastate)
{
    lua_pushcfunction(luastate, HasshGet);
    lua_setglobal(luastate, "HasshGet");

    lua_pushcfunction(luastate, HasshGetString);
    lua_setglobal(luastate, "HasshGetString");

    lua_pushcfunction(luastate, HasshServerGet);
    lua_setglobal(luastate, "HasshServerGet");

    lua_pushcfunction(luastate, HasshServerGetString);
    lua_setglobal(luastate, "HasshServerGetString");

    return 0;
}

#endif /* HAVE_LUA */
