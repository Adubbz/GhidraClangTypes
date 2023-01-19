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

public class SaveException extends Exception
{
    public SaveException(SaveErrorCode code)
    {
        super(getMessage(code));
    }

    public SaveException(int code)
    {
        this(SaveErrorCode.fromInteger(code));
    }

    private static String getMessage(SaveErrorCode code)
    {
        switch (code)
        {
            case NONE:
                return "No save error occurred";

            case UNKNOWN:
                return "An unknown save error occurred";

            case TRANSLATION_ERRORS:
                return "An error occurred during translation";

            case INVALID_TU:
                return "The translation unit to be saved is invalid";

            default:
                return "An unknown save error occurred";
        }
    }
}
