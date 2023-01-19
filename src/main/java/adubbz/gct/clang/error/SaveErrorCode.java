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

public enum SaveErrorCode
{
    NONE(0),
    UNKNOWN(1),
    TRANSLATION_ERRORS(2),
    INVALID_TU(3);

    private static HashMap<Integer, SaveErrorCode> byCode = new HashMap<>();

    private final int code;

    SaveErrorCode(int code)
    {
        this.code = code;
    }

    public static SaveErrorCode fromInteger(int code)
    {
        if (!byCode.containsKey(code))
            throw new RuntimeException("Unknown save error " + code);

        return byCode.get(code);
    }

    static
    {
        EnumSet.allOf(SaveErrorCode.class).forEach(e -> byCode.put(e.code, e));
    }
}
