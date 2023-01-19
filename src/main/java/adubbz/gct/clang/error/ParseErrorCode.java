/**
 * Copyright 2023 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted,
 * provided that the above copyright notice and this permission notice appear in all copies.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.gct.clang.error;

import java.util.EnumSet;
import java.util.HashMap;

public enum ParseErrorCode
{
    SUCCESS(0),
    FAILURE(1),
    CRASHED(2),
    INVALID_ARGUMENTS(3),
    AST_READ_ERROR(4);

    private static HashMap<Integer, ParseErrorCode> byCode = new HashMap<>();

    private final int code;

    ParseErrorCode(int code)
    {
        this.code = code;
    }

    public static ParseErrorCode fromInteger(int code)
    {
        if (!byCode.containsKey(code))
            throw new RuntimeException("Unknown parse error " + code);

        return byCode.get(code);
    }

    static
    {
        EnumSet.allOf(ParseErrorCode.class).forEach(e -> byCode.put(e.code, e));
    }
}
