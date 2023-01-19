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

public class ParseException extends Exception
{
    public ParseException(ParseErrorCode code)
    {
        super(getMessage(code));
    }

    public ParseException(int code)
    {
        this(ParseErrorCode.fromInteger(code));
    }

    private static String getMessage(ParseErrorCode code)
    {
        switch (code)
        {
            case SUCCESS:
                return "No libclang error occurred";

            case FAILURE:
                return "A generic libclang error occurred";

            case CRASHED:
                return "libclang crashed while performing the requested operation";

            case INVALID_ARGUMENTS:
                return "The function detected that the arguments violate the function contract";

            case AST_READ_ERROR:
                return "An AST deserialization error has occurred";

            default:
                return "An unknown libclang error occurred";
        }
    }
}
