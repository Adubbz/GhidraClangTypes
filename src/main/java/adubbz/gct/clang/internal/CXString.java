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
package adubbz.gct.clang.internal;

import adubbz.gct.GCTPlugin;
import adubbz.gct.clang.internal.pointer.TranslationUnitPointer;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.lang.ref.Cleaner;

@Structure.FieldOrder({"data", "privateFlags"})
public class CXString extends Structure
{
    public Pointer data;
    public int privateFlags;

    public static class ByValue extends CXString implements Structure.ByValue, AutoCloseable
    {
        @Override
        public String toString()
        {
            return LibClang.INSTANCE.clang_getCString(this);
        }

        @Override
        public void close()
        {
            LibClang.INSTANCE.clang_disposeString(this);
        }

        @Override
        public void finalize() throws Throwable
        {
            try
            {
                this.close();
            }
            finally
            {
                super.finalize();
            }
        }
    }
}
