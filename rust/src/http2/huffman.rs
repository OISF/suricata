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

use nom7::bits::streaming::take as take_bits;
use nom7::branch::alt;
use nom7::combinator::{complete, map_opt};
use nom7::error::{make_error, ErrorKind};
use nom7::{Err, IResult};

fn http2_huffman_table_len5(n: u32) -> Option<u8> {
    match n {
        0 => Some(48),
        1 => Some(49),
        2 => Some(50),
        3 => Some(97),
        4 => Some(99),
        5 => Some(101),
        6 => Some(105),
        7 => Some(111),
        8 => Some(115),
        9 => Some(116),
        _ => None,
    }
}

fn http2_decode_huffman_len5(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(5u32), http2_huffman_table_len5))(input)
}

fn http2_huffman_table_len6(n: u32) -> Option<u8> {
    match n {
        0x14 => Some(32),
        0x15 => Some(37),
        0x16 => Some(45),
        0x17 => Some(46),
        0x18 => Some(47),
        0x19 => Some(51),
        0x1a => Some(52),
        0x1b => Some(53),
        0x1c => Some(54),
        0x1d => Some(55),
        0x1e => Some(56),
        0x1f => Some(57),
        0x20 => Some(61),
        0x21 => Some(65),
        0x22 => Some(95),
        0x23 => Some(98),
        0x24 => Some(100),
        0x25 => Some(102),
        0x26 => Some(103),
        0x27 => Some(104),
        0x28 => Some(108),
        0x29 => Some(109),
        0x2a => Some(110),
        0x2b => Some(112),
        0x2c => Some(114),
        0x2d => Some(117),
        _ => None,
    }
}

fn http2_decode_huffman_len6(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(6u32), http2_huffman_table_len6))(input)
}

fn http2_huffman_table_len7(n: u32) -> Option<u8> {
    match n {
        0x5c => Some(58),
        0x5d => Some(66),
        0x5e => Some(67),
        0x5f => Some(68),
        0x60 => Some(69),
        0x61 => Some(70),
        0x62 => Some(71),
        0x63 => Some(72),
        0x64 => Some(73),
        0x65 => Some(74),
        0x66 => Some(75),
        0x67 => Some(76),
        0x68 => Some(77),
        0x69 => Some(78),
        0x6a => Some(79),
        0x6b => Some(80),
        0x6c => Some(81),
        0x6d => Some(82),
        0x6e => Some(83),
        0x6f => Some(84),
        0x70 => Some(85),
        0x71 => Some(86),
        0x72 => Some(87),
        0x73 => Some(89),
        0x74 => Some(106),
        0x75 => Some(107),
        0x76 => Some(113),
        0x77 => Some(118),
        0x78 => Some(119),
        0x79 => Some(120),
        0x7a => Some(121),
        0x7b => Some(122),
        _ => None,
    }
}

fn http2_decode_huffman_len7(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(7u32), http2_huffman_table_len7))(input)
}

fn http2_huffman_table_len8(n: u32) -> Option<u8> {
    match n {
        0xf8 => Some(38),
        0xf9 => Some(42),
        0xfa => Some(44),
        0xfb => Some(59),
        0xfc => Some(88),
        0xfd => Some(90),
        _ => None,
    }
}

fn http2_decode_huffman_len8(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(8u32), http2_huffman_table_len8))(input)
}

fn http2_huffman_table_len10(n: u32) -> Option<u8> {
    match n {
        0x3f8 => Some(33),
        0x3f9 => Some(34),
        0x3fa => Some(40),
        0x3fb => Some(41),
        0x3fc => Some(63),
        _ => None,
    }
}

fn http2_decode_huffman_len10(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(10u32), http2_huffman_table_len10))(input)
}

fn http2_huffman_table_len11(n: u32) -> Option<u8> {
    match n {
        0x7fa => Some(39),
        0x7fb => Some(43),
        0x7fc => Some(124),
        _ => None,
    }
}

fn http2_decode_huffman_len11(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(11u32), http2_huffman_table_len11))(input)
}

fn http2_huffman_table_len12(n: u32) -> Option<u8> {
    match n {
        0xffa => Some(35),
        0xffb => Some(62),
        _ => None,
    }
}

fn http2_decode_huffman_len12(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(12u32), http2_huffman_table_len12))(input)
}

fn http2_huffman_table_len13(n: u32) -> Option<u8> {
    match n {
        0x1ff8 => Some(0),
        0x1ff9 => Some(36),
        0x1ffa => Some(64),
        0x1ffb => Some(91),
        0x1ffc => Some(93),
        0x1ffd => Some(126),
        _ => None,
    }
}

fn http2_decode_huffman_len13(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(13u32), http2_huffman_table_len13))(input)
}

fn http2_huffman_table_len14(n: u32) -> Option<u8> {
    match n {
        0x3ffc => Some(94),
        0x3ffd => Some(125),
        _ => None,
    }
}

fn http2_decode_huffman_len14(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(14u32), http2_huffman_table_len14))(input)
}

fn http2_huffman_table_len15(n: u32) -> Option<u8> {
    match n {
        0x7ffc => Some(60),
        0x7ffd => Some(96),
        0x7ffe => Some(123),
        _ => None,
    }
}

fn http2_decode_huffman_len15(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(15u32), http2_huffman_table_len15))(input)
}

fn http2_huffman_table_len19(n: u32) -> Option<u8> {
    match n {
        0x7fff0 => Some(92),
        0x7fff1 => Some(195),
        0x7fff2 => Some(208),
        _ => None,
    }
}

fn http2_decode_huffman_len19(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(19u32), http2_huffman_table_len19))(input)
}

fn http2_huffman_table_len20(n: u32) -> Option<u8> {
    match n {
        0xfffe6 => Some(128),
        0xfffe7 => Some(130),
        0xfffe8 => Some(131),
        0xfffe9 => Some(162),
        0xfffea => Some(184),
        0xfffeb => Some(194),
        0xfffec => Some(224),
        0xfffed => Some(226),
        _ => None,
    }
}

fn http2_decode_huffman_len20(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(20u32), http2_huffman_table_len20))(input)
}

fn http2_huffman_table_len21(n: u32) -> Option<u8> {
    match n {
        0x1fffdc => Some(153),
        0x1fffdd => Some(161),
        0x1fffde => Some(167),
        0x1fffdf => Some(172),
        0x1fffe0 => Some(176),
        0x1fffe1 => Some(177),
        0x1fffe2 => Some(179),
        0x1fffe3 => Some(209),
        0x1fffe4 => Some(216),
        0x1fffe5 => Some(217),
        0x1fffe6 => Some(227),
        0x1fffe7 => Some(229),
        0x1fffe8 => Some(230),
        _ => None,
    }
}

fn http2_decode_huffman_len21(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(21u32), http2_huffman_table_len21))(input)
}

fn http2_huffman_table_len22(n: u32) -> Option<u8> {
    match n {
        0x3fffd2 => Some(129),
        0x3fffd3 => Some(132),
        0x3fffd4 => Some(133),
        0x3fffd5 => Some(134),
        0x3fffd6 => Some(136),
        0x3fffd7 => Some(146),
        0x3fffd8 => Some(154),
        0x3fffd9 => Some(156),
        0x3fffda => Some(160),
        0x3fffdb => Some(163),
        0x3fffdc => Some(164),
        0x3fffdd => Some(169),
        0x3fffde => Some(170),
        0x3fffdf => Some(173),
        0x3fffe0 => Some(178),
        0x3fffe1 => Some(181),
        0x3fffe2 => Some(185),
        0x3fffe3 => Some(186),
        0x3fffe4 => Some(187),
        0x3fffe5 => Some(189),
        0x3fffe6 => Some(190),
        0x3fffe7 => Some(196),
        0x3fffe8 => Some(198),
        0x3fffe9 => Some(228),
        0x3fffea => Some(232),
        0x3fffeb => Some(233),
        _ => None,
    }
}

fn http2_decode_huffman_len22(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(22u32), http2_huffman_table_len22))(input)
}

fn http2_huffman_table_len23(n: u32) -> Option<u8> {
    match n {
        0x7fffd8 => Some(1),
        0x7fffd9 => Some(135),
        0x7fffda => Some(137),
        0x7fffdb => Some(138),
        0x7fffdc => Some(139),
        0x7fffdd => Some(140),
        0x7fffde => Some(141),
        0x7fffdf => Some(143),
        0x7fffe0 => Some(147),
        0x7fffe1 => Some(149),
        0x7fffe2 => Some(150),
        0x7fffe3 => Some(151),
        0x7fffe4 => Some(152),
        0x7fffe5 => Some(155),
        0x7fffe6 => Some(157),
        0x7fffe7 => Some(158),
        0x7fffe8 => Some(165),
        0x7fffe9 => Some(166),
        0x7fffea => Some(168),
        0x7fffeb => Some(174),
        0x7fffec => Some(175),
        0x7fffed => Some(180),
        0x7fffee => Some(182),
        0x7fffef => Some(183),
        0x7ffff0 => Some(188),
        0x7ffff1 => Some(191),
        0x7ffff2 => Some(197),
        0x7ffff3 => Some(231),
        0x7ffff4 => Some(239),
        _ => None,
    }
}

fn http2_decode_huffman_len23(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(23u32), http2_huffman_table_len23))(input)
}

fn http2_huffman_table_len24(n: u32) -> Option<u8> {
    match n {
        0xffffea => Some(9),
        0xffffeb => Some(142),
        0xffffec => Some(144),
        0xffffed => Some(145),
        0xffffee => Some(148),
        0xffffef => Some(159),
        0xfffff0 => Some(171),
        0xfffff1 => Some(206),
        0xfffff2 => Some(215),
        0xfffff3 => Some(225),
        0xfffff4 => Some(236),
        0xfffff5 => Some(237),
        _ => None,
    }
}

fn http2_decode_huffman_len24(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(24u32), http2_huffman_table_len24))(input)
}

fn http2_huffman_table_len25(n: u32) -> Option<u8> {
    match n {
        0x1ffffec => Some(199),
        0x1ffffed => Some(207),
        0x1ffffee => Some(234),
        0x1ffffef => Some(235),
        _ => None,
    }
}

fn http2_decode_huffman_len25(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(25u32), http2_huffman_table_len25))(input)
}

fn http2_huffman_table_len26(n: u32) -> Option<u8> {
    match n {
        0x3ffffe0 => Some(192),
        0x3ffffe1 => Some(193),
        0x3ffffe2 => Some(200),
        0x3ffffe3 => Some(201),
        0x3ffffe4 => Some(202),
        0x3ffffe5 => Some(205),
        0x3ffffe6 => Some(210),
        0x3ffffe7 => Some(213),
        0x3ffffe8 => Some(218),
        0x3ffffe9 => Some(219),
        0x3ffffea => Some(238),
        0x3ffffeb => Some(240),
        0x3ffffec => Some(242),
        0x3ffffed => Some(243),
        0x3ffffee => Some(255),
        _ => None,
    }
}

fn http2_decode_huffman_len26((i, bit_offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(26u32), http2_huffman_table_len26))((i, bit_offset))
}

fn http2_huffman_table_len27(n: u32) -> Option<u8> {
    match n {
        0x7ffffde => Some(203),
        0x7ffffdf => Some(204),
        0x7ffffe0 => Some(211),
        0x7ffffe1 => Some(212),
        0x7ffffe2 => Some(214),
        0x7ffffe3 => Some(221),
        0x7ffffe4 => Some(222),
        0x7ffffe5 => Some(223),
        0x7ffffe6 => Some(241),
        0x7ffffe7 => Some(244),
        0x7ffffe8 => Some(245),
        0x7ffffe9 => Some(246),
        0x7ffffea => Some(247),
        0x7ffffeb => Some(248),
        0x7ffffec => Some(250),
        0x7ffffed => Some(251),
        0x7ffffee => Some(252),
        0x7ffffef => Some(253),
        0x7fffff0 => Some(254),
        _ => None,
    }
}

fn http2_decode_huffman_len27(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(27u32), http2_huffman_table_len27))(input)
}

fn http2_huffman_table_len28(n: u32) -> Option<u8> {
    match n {
        0xfffffe2 => Some(2),
        0xfffffe3 => Some(3),
        0xfffffe4 => Some(4),
        0xfffffe5 => Some(5),
        0xfffffe6 => Some(6),
        0xfffffe7 => Some(7),
        0xfffffe8 => Some(8),
        0xfffffe9 => Some(11),
        0xfffffea => Some(12),
        0xfffffeb => Some(14),
        0xfffffec => Some(15),
        0xfffffed => Some(16),
        0xfffffee => Some(17),
        0xfffffef => Some(18),
        0xffffff0 => Some(19),
        0xffffff1 => Some(20),
        0xffffff2 => Some(21),
        0xffffff3 => Some(23),
        0xffffff4 => Some(24),
        0xffffff5 => Some(25),
        0xffffff6 => Some(26),
        0xffffff7 => Some(27),
        0xffffff8 => Some(28),
        0xffffff9 => Some(29),
        0xffffffa => Some(30),
        0xffffffb => Some(31),
        0xffffffc => Some(127),
        0xffffffd => Some(220),
        0xffffffe => Some(249),
        _ => None,
    }
}

fn http2_decode_huffman_len28(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(28u32), http2_huffman_table_len28))(input)
}

fn http2_huffman_table_len30(n: u32) -> Option<u8> {
    match n {
        0x3ffffffc => Some(10),
        0x3ffffffd => Some(13),
        0x3ffffffe => Some(22),
        // 0x3fffffff => Some(256),
        _ => None,
    }
}

fn http2_decode_huffman_len30(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    complete(map_opt(take_bits(30u32), http2_huffman_table_len30))(input)
}

//hack to end many0 even if some bits are remaining
fn http2_decode_huffman_end(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    Err(Err::Error(make_error(input, ErrorKind::Eof)))
}

//we could profile and optimize performance here
pub fn http2_decode_huffman(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    // trait nom::branch::Alt is implemented for lists up to size 20,
    // so use nested `alt` as a workaround (see nom documentation for `alt`)
    alt((
        http2_decode_huffman_len5,
        http2_decode_huffman_len6,
        http2_decode_huffman_len7,
        http2_decode_huffman_len8,
        http2_decode_huffman_len10,
        http2_decode_huffman_len11,
        http2_decode_huffman_len12,
        http2_decode_huffman_len13,
        http2_decode_huffman_len14,
        http2_decode_huffman_len15,
        http2_decode_huffman_len19,
        http2_decode_huffman_len20,
        http2_decode_huffman_len21,
        http2_decode_huffman_len21,
        http2_decode_huffman_len22,
        http2_decode_huffman_len23,
        http2_decode_huffman_len24,
        http2_decode_huffman_len25,
        http2_decode_huffman_len26,
        http2_decode_huffman_len27,
        alt((
            http2_decode_huffman_len28,
            http2_decode_huffman_len30,
            http2_decode_huffman_end,
        )),
    ))(input)
}
