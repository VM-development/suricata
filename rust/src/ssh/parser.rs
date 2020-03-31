/* Copyright (C) 2018 Open Information Security Foundation
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

//nom5 use nom::bytes::complete::is_not;
use nom::{be_u32, be_u8, rest};

#[inline]
fn is_not_lineend(b: u8) -> bool {
    if b == 10 || b == 13 {
        return false;
    }
    return true;
}

#[repr(u8)]
#[derive(PartialEq, Eq, FromPrimitive, Debug)]
pub enum MessageCode {
	SshMsgDisconnect = 1,
	SshMsgIgnore = 2,
	SshMsgUnimplemented = 3,
	SshMsgDebug = 4,
	SshMsgServiceRequest = 5,
	SshMsgServiceAccept = 6,
	SshMsgKexinit = 20,
	SshMsgNewKeys = 21,
	SshMsgKexdhInit = 30,
	SshMsgKexdhReply = 31,
	
	SshMsgUndefined,
}


//may leave \r at the end to be removed
named!(pub ssh_parse_line<&[u8], &[u8]>,
    terminated!(
        take_while!(is_not_lineend),
        alt!( tag!("\n") | tag!("\r\n") |
              do_parse!(
                    bytes: tag!("\r") >>
                    not!(eof!()) >> (bytes)
                )
            )
    )
);

#[derive(PartialEq)]
pub struct SshBanner<'a> {
    pub protover: &'a [u8],
    pub swver: &'a [u8],
}

impl<'a> SshBanner<'a> {}

// Could be simplified adding dummy \n at the end
// or use nom5 nom::bytes::complete::is_not
named!(pub ssh_parse_banner<SshBanner>,
    do_parse!(
        tag!("SSH-") >>
        protover: is_not!("-") >>
        char!('-') >>
        swver: alt!( complete!( is_not!(" \r") ) | rest ) >>
        //remaning after space is comments
        (SshBanner{protover, swver})
    )
);

//#[derive(PartialEq)]
#[derive(PartialEq, Debug)]
pub struct SshRecordHeader {
    pub pkt_len: u32,
    padding_len: u8,
    pub msg_code: MessageCode,
}

named!(pub ssh_parse_record_header<SshRecordHeader>,
    do_parse!(
        pkt_len: verify!(be_u32, |val:u32| val > 1) >>
        padding_len: be_u8 >>
        msg_code: be_u8 >>
        (SshRecordHeader{pkt_len: pkt_len,
        		padding_len: padding_len,
        		msg_code: num::FromPrimitive::from_u8(msg_code).unwrap_or(MessageCode::SshMsgUndefined)})
    )
);

//test for evasion against pkt_len=0or1...
named!(pub ssh_parse_record<SshRecordHeader>,
    do_parse!(
        pkt_len: verify!(be_u32, |val:u32| val > 1) >>
        padding_len: be_u8 >>
        msg_code: be_u8 >>
        take!((pkt_len-2) as usize) >>
        (SshRecordHeader{pkt_len: pkt_len,
        		 padding_len: padding_len, 
        		 msg_code: num::FromPrimitive::from_u8(msg_code).unwrap_or(MessageCode::SshMsgUndefined)})
    )
);



#[derive(Debug,PartialEq)]
pub struct SshPacketKeyExchange<'a> {
    pub cookie: &'a[u8],
    pub kex_algs: &'a [u8],
    pub server_host_key_algs: &'a [u8],
    pub encr_algs_client_to_server: &'a [u8],
    pub encr_algs_server_to_client: &'a [u8],
    pub mac_algs_client_to_server: &'a [u8],
    pub mac_algs_server_to_client: &'a [u8],
    pub comp_algs_client_to_server: &'a [u8],
    pub comp_algs_server_to_client: &'a [u8],
    pub langs_client_to_server: &'a [u8],
    pub langs_server_to_client: &'a [u8],
    pub first_kex_packet_follows: u8,
}

use md5::compute;

const SSH_HASSH_STRING_DELIMITER_SLICE: [u8; 1] = [b';'];

impl<'a> SshPacketKeyExchange<'a> {
    pub fn generate_hassh(&self, hassh_string: &mut Vec<u8>, hassh: &mut Vec<u8>, to_server: &bool) {
        let slices = if *to_server { 
            [self.kex_algs, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.encr_algs_server_to_client, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.mac_algs_server_to_client, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.comp_algs_server_to_client]}
        else {
            [self.kex_algs, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.encr_algs_client_to_server, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.mac_algs_client_to_server, &SSH_HASSH_STRING_DELIMITER_SLICE,
             self.comp_algs_client_to_server]
        };
        // reserving memory
        hassh_string.reserve_exact(slices.iter().fold(0, |acc, x| acc + x.len()));
        // copying slices to hassh string
        slices.iter().for_each(|&x| hassh_string.extend_from_slice(x)); 
        // hdr.hassh.extend_from_slice(compute(&hdr.hassh_string).0);
        hassh.extend(format!("{:x?}", compute(&hassh_string)).as_bytes());
    }
}

named!(parse_string<&[u8]>, do_parse!(
    len: be_u32 >>
    string: take!(len) >>
    ( string )
));

named!(pub parse_packet_key_exchange<SshPacketKeyExchange>, do_parse!(
    cookie: take!(16) >>
    kex_algs: parse_string >>
    server_host_key_algs: parse_string >>
    encr_algs_client_to_server: parse_string >>
    encr_algs_server_to_client: parse_string >>
    mac_algs_client_to_server: parse_string >>
    mac_algs_server_to_client: parse_string >>
    comp_algs_client_to_server: parse_string >>
    comp_algs_server_to_client: parse_string >>
    langs_client_to_server: parse_string >>
    langs_server_to_client: parse_string >>
    first_kex_packet_follows: be_u8 >>
    be_u32 >>
    ( SshPacketKeyExchange {
        cookie: cookie,
        kex_algs: kex_algs,
        server_host_key_algs: server_host_key_algs,
        encr_algs_client_to_server: encr_algs_client_to_server,
        encr_algs_server_to_client: encr_algs_server_to_client,
        mac_algs_client_to_server: mac_algs_client_to_server,
        mac_algs_server_to_client: mac_algs_server_to_client,
        comp_algs_client_to_server: comp_algs_client_to_server,
        comp_algs_server_to_client: comp_algs_server_to_client,
        langs_client_to_server: langs_client_to_server,
        langs_server_to_client: langs_server_to_client,
        first_kex_packet_follows: first_kex_packet_follows,
    } )
));

#[cfg(test)]
mod tests {

    use super::*;
    use md5::compute;

    /// Simple test of some valid data.
    #[test]
    fn test_ssh_parse_banner() {
        let buf = b"SSH-Single-";
        let result = ssh_parse_banner(buf);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message.protover, b"Single");
                assert_eq!(message.swver, b"");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2 = b"SSH-2.0-Soft";
        let result2 = ssh_parse_banner(buf2);
        match result2 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message.protover, b"2.0");
                assert_eq!(message.swver, b"Soft");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_line() {
        let buf = b"SSH-Single\n";
        let result = ssh_parse_line(buf);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Single");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2 = b"SSH-Double\r\n";
        let result2 = ssh_parse_line(buf2);
        match result2 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Double");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf3 = b"SSH-Oops\rMore\r\n";
        let result3 = ssh_parse_line(buf3);
        match result3 {
            Ok((rem, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Oops");
                assert_eq!(rem, b"More\r\n");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf4 = b"SSH-Miss\r";
        let result4 = ssh_parse_line(buf4);
        match result4 {
            Ok((_, _)) => {
                panic!("Expected incomplete result");
            }
            Err(nom::Err::Incomplete(_)) => {
                //OK
                assert_eq!(1, 1);
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf5 = b"\n";
        let result5 = ssh_parse_line(buf5);
        match result5 {
            Ok((_, message)) => {
                // Check empty line
                assert_eq!(message, b"");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_key_exchange() {
        let client_key_exchange: &'static [u8] = include_bytes!("client_init.raw");
        let cookie = [0x18, 0x70, 0xcb, 0xa4, 0xa3, 0xd4, 0xdc, 0x88, 0x6f, 0xfd, 0x76, 0x06, 0xcf, 0x36, 0x1b, 0xc6];
        let key_exchange = SshPacketKeyExchange {
            cookie: &cookie,
            kex_algs: b"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
            server_host_key_algs: b"ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
            encr_algs_client_to_server: b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            encr_algs_server_to_client: b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            mac_algs_client_to_server: b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            mac_algs_server_to_client: b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            comp_algs_client_to_server: b"none,zlib@openssh.com,zlib",
            comp_algs_server_to_client: b"none,zlib@openssh.com,zlib",
            langs_client_to_server: b"",
            langs_server_to_client: b"",
            first_kex_packet_follows: 0,
        };

        let expected = Ok((b"" as &[u8], key_exchange));
        let res = parse_packet_key_exchange(&client_key_exchange);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_parse_hassh() {
        let client_key_exchange: &'static [u8] = include_bytes!("client_init.raw");
        println!("print {:?}", &client_key_exchange);
        let mut hassh_string: Vec<u8> = vec!();
        let mut hassh: Vec<u8> = vec!();
        match parse_packet_key_exchange(&client_key_exchange){
            Ok((_, key_exchange)) => { key_exchange.generate_hassh(&mut hassh_string, &mut hassh, &true); }
            Err(_) => { }
        }

        assert_eq!(hassh_string,    "curve25519-sha256,curve25519-sha256@libssh.org,\
                                    ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,\
                                    diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,\
                                    diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,\
                                    aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,\
                                    umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,\
                                    hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,\
                                    hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib".as_bytes().to_vec());
        assert_eq!(hassh, "ec7378c1a92f5a8dde7e8b7a1ddf33d1".as_bytes().to_vec());
    }

    #[test]
    fn test_parse_hassh_server() {
        let client_key_exchange:  &'static [u8] = include_bytes!("server_init.raw");
        let mut hassh_server_string: Vec<u8> = vec!();
        let mut hassh_server: Vec<u8> = vec!();
        match parse_packet_key_exchange(&client_key_exchange){
            Ok((_, key_exchange)) => { key_exchange.generate_hassh(&mut hassh_server_string, &mut hassh_server, &true); }
            Err(_) => { }
        }

        assert_eq!(hassh_server_string, "curve25519-sha256,curve25519-sha256@libssh.org,\
                                        ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,\
                                        diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,\
                                        diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,\
                                        diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,\
                                        aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,\
                                        aes256-gcm@openssh.com;umac-64-etm@openssh.com,\
                                        umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,\
                                        hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,\
                                        umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,\
                                        hmac-sha2-512,hmac-sha1;none,zlib@openssh.com".as_bytes().to_vec());
        assert_eq!(hassh_server, "b12d2871a1189eff20364cf5333619ee".as_bytes().to_vec());
    }
}
