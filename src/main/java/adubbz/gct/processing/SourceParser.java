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
package adubbz.gct.processing;

import adubbz.gct.GCTPlugin;
import adubbz.gct.clang.Cursor;
import adubbz.gct.clang.CursorKind;
import adubbz.gct.clang.TranslationUnit;
import adubbz.gct.clang.UnsavedFile;
import adubbz.gct.clang.error.ParseException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import java.util.LinkedHashMap;

public class SourceParser
{
    private static final String CLANG_PREAMBLE =
"""
typedef char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
""".replace("\n", "");

    // TODO: Handle alignment (__attribute__((aligned(x))), alignas)

    public void parse(TypePool typePool, String source) throws ParseException
    {
        // Clear existing parsed types
        typePool.clearParsedTypes();

        TranslationUnit tu = new TranslationUnit.Builder("tmp.hpp").unsavedFiles(new UnsavedFile("tmp.hpp", CLANG_PREAMBLE + source)).parseIncomplete().skipFunctionBodies().build();
        Cursor rootCursor = tu.cursor();

        rootCursor.visitChildren((cursor, parent) ->
        {
            switch (cursor.kind())
            {
                case ENUM_DECL:
                    return parseEnum(typePool, cursor);

                case TYPEDEF_DECL:
                    return parseTypedef(typePool, cursor);

                case STRUCT_DECL:
                    return parseStruct(typePool, cursor);

                case UNION_DECL:
                    return parseUnion(typePool, cursor);
            }

           return Cursor.ChildVisitResult.RECURSE;
        });

        // DEBUG:
        // tu.cursor().visitChildren(new DebugVisitor(0));
    }

    private Cursor.ChildVisitResult parseEnum(TypePool pool, Cursor enumCursor)
    {
        ImmutableMap.Builder<String, Long> enumValueBuilder = ImmutableMap.builder();

        enumCursor.visitChildren((cursor, parent) ->
        {
            if (cursor.kind() == CursorKind.ENUM_CONSTANT_DECL)
            {
                enumValueBuilder.put(cursor.spelling(), cursor.enumValue());
            }

            return Cursor.ChildVisitResult.CONTINUE;
        });

        pool.addParsedType(new ParsedEnum(enumCursor.spelling(), enumCursor.enumType().getSize(), enumValueBuilder.build()));
        return Cursor.ChildVisitResult.CONTINUE;
    }

    private Cursor.ChildVisitResult parseTypedef(TypePool pool, Cursor cursor)
    {
        pool.addParsedType(new ParsedTypedef(cursor.spelling(), cursor.underlyingTypedefType().spelling()));
        return Cursor.ChildVisitResult.CONTINUE;
    }

    private Cursor.ChildVisitResult parseStruct(TypePool pool, Cursor structCursor)
    {
        LinkedHashMap<String, String> fieldMap = new LinkedHashMap<>();

        structCursor.visitChildren((cursor, parent) ->
        {
            if (cursor.kind() == CursorKind.FIELD_DECL)
            {
                fieldMap.put(cursor.spelling(), cursor.type().spelling());
            }

            return Cursor.ChildVisitResult.CONTINUE;
        });

        pool.addParsedType(new ParsedStructure(structCursor.spelling(), fieldMap));
        return Cursor.ChildVisitResult.CONTINUE;
    }

    private Cursor.ChildVisitResult parseUnion(TypePool pool, Cursor unionCursor)
    {
        LinkedHashMap<String, String> fieldMap = new LinkedHashMap<>();

        unionCursor.visitChildren((cursor, parent) ->
        {
            if (cursor.kind() == CursorKind.FIELD_DECL)
            {
                fieldMap.put(cursor.spelling(), cursor.type().spelling());
            }

            return Cursor.ChildVisitResult.CONTINUE;
        });

        pool.addParsedType(new ParsedUnion(unionCursor.spelling(), fieldMap));
        return Cursor.ChildVisitResult.CONTINUE;
    }

    private static class DebugVisitor implements Cursor.CursorVisitor
    {
        private final int level;

        private DebugVisitor(int level)
        {
            this.level = level;
        }

        @Override
        public Cursor.ChildVisitResult apply(Cursor cursor, Cursor parent)
        {
            GCTPlugin.LOGGER.info("-".repeat(this.level) + " " + cursor.kind());
            cursor.visitChildren(new DebugVisitor(this.level+1));
            return Cursor.ChildVisitResult.CONTINUE;
        }
    }
}
