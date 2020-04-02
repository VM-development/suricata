/* Copyright (C) 2020 Open Information Security Foundation
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

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use super::ssh::SSHTransaction;
use std::ptr;

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_protocol(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOSERVER => {
            let m = &tx.cli_hdr.protover;
            if m.len() > 0 {
                unsafe { *buffer = m.as_ptr() };
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        STREAM_TOCLIENT => {
            let m = &tx.srv_hdr.protover;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_software(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOSERVER => {
            let m = &tx.cli_hdr.swver;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        STREAM_TOCLIENT => {
            let m = &tx.srv_hdr.swver;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_hassh(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOSERVER => {
            let m = &tx.cli_hdr.hassh;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_hassh_server(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOCLIENT => {
            let m = &tx.srv_hdr.hassh;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_hassh_string(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOSERVER => {
            let m = &tx.cli_hdr.hassh_string;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_hassh_server_string(
    tx: *mut std::os::raw::c_void,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction {
        STREAM_TOCLIENT => {
            let m = &tx.srv_hdr.hassh_string;
            if m.len() > 0 {
                unsafe {
                    *buffer = m.as_ptr();
                }
                unsafe {
                    *buffer_len = m.len() as u32;
                }
                return 1;
            }
        }
        _ => {}
    }
    unsafe {
        *buffer = ptr::null();
    }
    unsafe {
        *buffer_len = 0;
    }

    return 0;
}