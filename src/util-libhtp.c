/*
 * We are using this file to hold APIs copied from libhtp 0.5.x.
 */

/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * Paul Gofran <paul.gofran@lmco.com>
 */


/**
 * \brief A direct flick off libhtp-0.5.x htp_is_lws().
 */
int SC_htp_is_lws(int c)
{
    if ((c == ' ') || (c == '\t')) return 1;
    else return 0;
}

/**
 * Is character a white space character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int SC_htp_is_space(int c) {
    switch (c) {
        case ' ':
        case '\f':
        case '\v':
        case '\t':
        case '\r':
        case '\n':
            return 1;
        default:
            return 0;
    }
}

/**
 * Is character a separator character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int SC_htp_is_separator(int c) {
    /* separators = "(" | ")" | "<" | ">" | "@"
                  | "," | ";" | ":" | "\" | <">
                  | "/" | "[" | "]" | "?" | "="
                  | "{" | "}" | SP | HT         */
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return 1;
            break;
        default:
            return 0;
    }
}


/**
 * Is character a token character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int SC_htp_is_token(int c) {
    /* token = 1*<any CHAR except CTLs or separators> */
    /* CHAR  = <any US-ASCII character (octets 0 - 127)> */
    if ((c < 32) || (c > 126))
        return 0;
    if (SC_htp_is_separator(c))
        return 0;
    return 1;
}
