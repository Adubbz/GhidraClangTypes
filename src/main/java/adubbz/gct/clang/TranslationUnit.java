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

import adubbz.gct.clang.error.ParseException;
import adubbz.gct.clang.error.SaveException;
import adubbz.gct.clang.internal.JNAUtil;
import adubbz.gct.clang.internal.LibClang;
import adubbz.gct.clang.internal.pointer.TranslationUnitPointer;
import com.google.common.base.Preconditions;
import com.google.common.collect.UnmodifiableListIterator;

import java.lang.ref.Cleaner;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Represents a source code translation unit.
 * This is one of the main types in the API. Any time you wish to interact
 * with Clang's representation of a source file, you typically start with a
 * translation unit.
 */
public final class TranslationUnit implements AutoCloseable
{
    private static final Cleaner CLEANER = Cleaner.create();

    /** Default parsing mode. */
    private static final int PARSE_NONE = 0;

    private static final int PARSE_DETAILED_PROCESSING_RECORD = 1;

    private static final int PARSE_INCOMPLETE = 2;

    private static final int PARSE_PRECOMPILED_PREAMBLE = 4;

    private static final int PARSE_CACHE_COMPLETION_RESULTS = 8;

    // Flags with values 16 and 32 are deprecated and intentionally omitted.

    private static final int PARSE_SKIP_FUNCTION_BODIES = 64;

    private static final int PARSE_INCLUDE_BRIEF_COMMENTS_IN_CODE_COMPLETION = 128;

    private final Index index;
    private final TranslationUnitPointer self;
    private final Cleaner.Cleanable cleanable;

    private TranslationUnit(TranslationUnitPointer self, Index index)
    {
        Preconditions.checkNotNull(self);
        Preconditions.checkNotNull(index);
        this.self = self;
        this.index = index;
        this.cleanable = CLEANER.register(this, new Dispose(this.self));
    }

    public Cursor cursor()
    {
        return new Cursor(LibClang.INSTANCE.clang_getTranslationUnitCursor(this.self));
    }

    public Iterator<Diagnostic> diagnostics()
    {
        return new UnmodifiableListIterator<Diagnostic>()
        {
            private final int size;
            private int position;

            {
                this.size = LibClang.INSTANCE.clang_getNumDiagnostics(TranslationUnit.this.getPointer());
                this.position = 0;
            }

            protected Diagnostic get(int index)
            {
                return new Diagnostic(LibClang.INSTANCE.clang_getDiagnostic(TranslationUnit.this.getPointer(), index));
            }

            @Override
            public boolean hasNext()
            {
                return this.position < this.size;
            }

            @Override
            public Diagnostic next()
            {
                if (!this.hasNext())
                    throw new NoSuchElementException();
                else
                    return this.get(this.position++);
            }

            @Override
            public int nextIndex()
            {
                return this.position;
            }

            @Override
            public boolean hasPrevious()
            {
                return this.position > 0;
            }

            @Override
            public Diagnostic previous()
            {
                if (!this.hasPrevious())
                    throw new NoSuchElementException();
                else
                    return this.get(--this.position);
            }

            @Override
            public int previousIndex()
            {
                return this.position - 1;
            }
        };
    }

    public void save(String filename) throws SaveException
    {
        int options = LibClang.INSTANCE.clang_defaultSaveOptions(this.self);
        int result = LibClang.INSTANCE.clang_saveTranslationUnit(this.self, filename, options);
        if (result != 0) throw new SaveException(result);
    }

    @Override
    public void close()
    {
        this.cleanable.clean();
    }

    protected TranslationUnitPointer getPointer()
    {
        return this.self;
    }

    public static class Builder
    {
        private String sourceFilename;
        private String[] commandLineArgs;
        private UnsavedFile[] unsavedFiles;
        private int options;

        public Builder(String sourceFilename)
        {
            this.sourceFilename = sourceFilename;
            this.options = PARSE_NONE;
        }

        /**
         * Command-line arguments that would be passed to clang are specified as
         * a list via args. These can be used to specify include paths, warnings,
         * etc. e.g. ["-Wall", "-I/path/to/include"].
         * @param args command line arguments.
         * @return the current builder.
         */
        public Builder args(String... args)
        {
            this.commandLineArgs = args;
            return this;
        }

        public Builder unsavedFiles(UnsavedFile... files)
        {
            if (files.length > 0)
            {
                this.unsavedFiles = JNAUtil.makeContiguousArray(files);
            }

            return this;
        }

        /**
         * Instruct the parser to create a detailed processing record containing
         * metadata not normally retained.
         * @return the current builder.
         */
        public Builder detailedProcessingRecord()
        {
            this.options |= PARSE_DETAILED_PROCESSING_RECORD;
            return this;
        }

        /**
         * Indicates that the translation unit is incomplete. This is typically used
         * when parsing headers.
         * @return the current builder.
         */
        public Builder parseIncomplete()
        {
            this.options |= PARSE_INCOMPLETE;
            return this;
        }

        /**
         * Instruct the parser to create a pre-compiled preamble for the translation
         * unit. This caches the preamble (included files at top of source file).
         * This is useful if the translation unit will be reparsed and you don't
         * want to incur the overhead of reparsing the preamble.
         * @return the current builder.
         */
        public Builder precompiledPreamble()
        {
            this.options |= PARSE_PRECOMPILED_PREAMBLE;
            return this;
        }

        /**
         * Cache code completion information on parse. This adds time to parsing but
         * speeds up code completion.
         * @return the current builder.
         */
        public Builder cacheCompletionResults()
        {
           this.options |= PARSE_CACHE_COMPLETION_RESULTS;
           return this;
        }

        /**
         * Do not parse function bodies. This is useful if you only care about
         * searching for declarations/definitions.
         * @return the current builder.
         */
        public Builder skipFunctionBodies()
        {
           this.options |= PARSE_SKIP_FUNCTION_BODIES;
           return this;
        }

        /**
         * Used to indicate that brief documentation comments should be included
         * into the set of code completions returned from this translation unit.
         * @return the current builder.
         */
        public Builder includeBriefCommentsInCodeCompletion()
        {
            this.options |= PARSE_INCLUDE_BRIEF_COMMENTS_IN_CODE_COMPLETION;
            return this;
        }

        public TranslationUnit build(Index index) throws ParseException
        {
            if (index == null)
                index = Index.create();

            int commandLineArgsLen = this.commandLineArgs != null ? this.commandLineArgs.length : 0;
            int unsavedFilesLen = this.unsavedFiles != null ? this.unsavedFiles.length : 0;

            TranslationUnitPointer[] outTU = new TranslationUnitPointer[1];
            int result = LibClang.INSTANCE.clang_parseTranslationUnit2(index.getPointer(), this.sourceFilename, this.commandLineArgs, commandLineArgsLen, this.unsavedFiles, unsavedFilesLen, this.options, outTU);

            if (result != 0)
                throw new ParseException(result);

            return new TranslationUnit(outTU[0], index);
        }

        public TranslationUnit build() throws ParseException
        {
            return build(null);
        }
    }

    static class Dispose implements Runnable
    {
        private final TranslationUnitPointer pointer;

        private Dispose(TranslationUnitPointer p)
        {
            this.pointer = p;
        }
        @Override
        public void run()
        {
            LibClang.INSTANCE.clang_disposeTranslationUnit(this.pointer);
        }
    }
}
