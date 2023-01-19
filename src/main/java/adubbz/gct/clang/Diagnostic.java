/**
 * Copyright 2023 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted,
 * provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.gct.clang;

import adubbz.gct.clang.internal.LibClang;
import adubbz.gct.clang.internal.pointer.DiagnosticPointer;
import com.google.common.base.Preconditions;

import java.lang.ref.Cleaner;

/**
 * A Diagnostic is a single instance of a Clang diagnostic. It includes the
 * diagnostic severity, the message, the location the diagnostic occurred, as
 * well as additional source ranges and associated fix-it hints.
 */
public class Diagnostic implements AutoCloseable
{
    private static final Cleaner CLEANER = Cleaner.create();

    private final DiagnosticPointer self;
    private final Cleaner.Cleanable cleanable;

    protected Diagnostic(DiagnosticPointer self)
    {
        Preconditions.checkNotNull(self);
        this.self = self;
        this.cleanable = CLEANER.register(this, new Dispose(this.self));
    }

    public String format(DisplayOptions options)
    {
        final int optionsVal = options == null ? LibClang.INSTANCE.clang_defaultDiagnosticDisplayOptions() : options.value();
        return LibClang.INSTANCE.clang_formatDiagnostic(this.self, optionsVal).toString();
    }

    public String format() throws Exception
    {
        return this.format(null);
    }

    @Override
    public void close()
    {
        this.cleanable.clean();
    }

    public record DisplayOptions(int value)
    {
        public static final int DIAGNOSTIC_DISPLAY_SOURCE_LOCATION = 0x1;
        public static final int DIAGNOSTIC_DISPLAY_COLUMN = 0x2;
        public static final int DIAGNOSTIC_DISPLAY_SOURCE_RANGES = 0x4;

        public static final int DIAGNOSTIC_DISPLAY_OPTION = 0x8;
        public static final int DIAGNOSTIC_DISPLAY_CATEGORY_ID = 0x10;
        public static final int DIAGNOSTIC_DISPLAY_CATEGORY_NAME = 0x20;
    }

    static class Dispose implements Runnable
    {
        private final DiagnosticPointer pointer;

        private Dispose(DiagnosticPointer p)
        {
            this.pointer = p;
        }
        @Override
        public void run()
        {
            LibClang.INSTANCE.clang_disposeDiagnostic(this.pointer);
        }
    }
}
