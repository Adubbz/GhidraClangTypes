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
import adubbz.gct.clang.internal.pointer.IndexPointer;
import com.google.common.base.Preconditions;

import java.lang.ref.Cleaner;

/**
 * The Index type provides the primary interface to the Clang CIndex library,
 * primarily by providing an interface for reading and parsing translation
 * units.
 */
public final class Index implements AutoCloseable
{
    private static final Cleaner CLEANER = Cleaner.create();

    private final IndexPointer self;
    private final Cleaner.Cleanable cleanable;

    private Index(IndexPointer self)
    {
        Preconditions.checkNotNull(self);
        this.self = self;
        this.cleanable = CLEANER.register(this, new Dispose(this.self));
    }

    @Override
    public void close()
    {
        this.cleanable.clean();
    }

    protected IndexPointer getPointer()
    {
        return this.self;
    }

    /**
     * Create a new Index.
     * @param excludeDecls Exclude local declarations from translation units.
     * @return the newly created index.
     */
    public static Index create(boolean excludeDecls)
    {
        return new Index(LibClang.INSTANCE.clang_createIndex(excludeDecls, false));
    }

    /**
     * Create a new Index.
     * @return the newly created index.
     */
    public static Index create()
    {
        return create(false);
    }

    static class Dispose implements Runnable
    {
        private final IndexPointer pointer;

        private Dispose(IndexPointer p)
        {
            this.pointer = p;
        }
        @Override
        public void run()
        {
            LibClang.INSTANCE.clang_disposeIndex(this.pointer);
        }
    }
}
