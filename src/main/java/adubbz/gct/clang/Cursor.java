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

import adubbz.gct.clang.internal.CXCursor;
import adubbz.gct.clang.internal.LibClang;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.sun.jna.FromNativeContext;
import com.sun.jna.platform.EnumConverter;
import org.python.antlr.ast.If;
import org.python.antlr.ast.Return;

import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

/**
 * A cursor representing some element in the abstract syntax tree for
 * a translation unit.
 *
 * The cursor abstraction unifies the different kinds of entities in a
 * program--declaration, statements, expressions, references to declarations,
 * etc.--under a single "cursor" abstraction with a common set of operations.
 * Common operation for a cursor include: getting the physical location in
 * a source file where the cursor points, getting the name associated with a
 * cursor, and retrieving cursors for any child nodes of a particular cursor.
 */
public class Cursor
{
    private final CXCursor.ByValue self;

    private final Supplier<CursorKind> kind;
    private final Supplier<String> spelling;
    private final Supplier<String> displayName;
    private final Supplier<Type> type;
    private final Supplier<Type> underlyingTypedefType;
    private final Supplier<Type> enumType;
    public final Supplier<Long> enumValue;

    protected Cursor(CXCursor.ByValue self)
    {
        Preconditions.checkNotNull(self);
        this.self = self;
        this.kind = Suppliers.memoize(() -> LibClang.INSTANCE.clang_getCursorKind(this.self));
        this.spelling = Suppliers.memoize(() -> LibClang.INSTANCE.clang_getCursorSpelling(this.self).toString());
        this.displayName = Suppliers.memoize(() -> LibClang.INSTANCE.clang_getCursorDisplayName(this.self).toString());
        this.type = Suppliers.memoize(() -> new Type(LibClang.INSTANCE.clang_getCursorType(this.self)));
        this.underlyingTypedefType = Suppliers.memoize(() -> {
            Preconditions.checkArgument(this.kind().isDeclaration(), "Cursor must be a declaration");
            return new Type(LibClang.INSTANCE.clang_getTypedefDeclUnderlyingType(this.self));
        });
        this.enumType = Suppliers.memoize(() -> {
            Preconditions.checkArgument(this.kind() == CursorKind.ENUM_DECL, "Cursor must be an enum");
            return new Type(LibClang.INSTANCE.clang_getEnumDeclIntegerType(this.self));
        });
        this.enumValue = Suppliers.memoize(() -> {
            Preconditions.checkArgument(this.kind() == CursorKind.ENUM_CONSTANT_DECL, "Cursor must be an enum constant");
            var underlyingType = this.type();

            //Figure out the underlying type of the enum to know if it is a signed or unsigned quantity.
            if (underlyingType.kind() == TypeKind.ENUM)
                underlyingType = underlyingType.getDeclaration().enumType();

            if (List.of(TypeKind.CHAR_U, TypeKind.U_CHAR, TypeKind.CHAR16, TypeKind.CHAR32, TypeKind.U_SHORT, TypeKind.U_INT,
                        TypeKind.U_LONG, TypeKind.U_LONG_LONG, TypeKind.U_INT128).contains(underlyingType.kind()))
            {
                return LibClang.INSTANCE.clang_getEnumConstantDeclUnsignedValue(this.self);
            }
            else
            {
                return LibClang.INSTANCE.clang_getEnumConstantDeclValue(this.self);
            }
        });
    }

    /**
     * Return the kind of this cursor.
     */
    public CursorKind kind()
    {
        return this.kind.get();
    }

    /**
     * Return the spelling of the entity pointed at by the cursor.
     */
    public String spelling()
    {
        return this.spelling.get();
    }

    /**
     * Return the display name for the entity referenced by this cursor.
     *
     * The display name contains extra information that helps identify the
     * cursor, such as the parameters of a function or template or the
     * arguments of a class template specialization.
     */
    public String displayName()
    {
        return this.displayName.get();
    }

    /**
     * Retrieve the Type (if any) of the entity pointed at by the cursor.
     */
    public Type type()
    {
        return this.type.get();
    }

    /**
     * Return the underlying type of a typedef declaration.
     *
     * Returns a Type for the typedef this cursor is a declaration for. If
     * the current cursor is not a typedef, this raises.
     */
    public Type underlyingTypedefType()
    {
        return this.underlyingTypedefType.get();
    }

    /**
     * Return the integer type of an enum declaration.
     *
     * Returns a Type corresponding to an integer. If the cursor is not for an
     * enum, this raises.
     */
    public Type enumType()
    {
        return this.enumType.get();
    }

    /**
     * Return the value of an enum constant.
     */
    public long enumValue()
    {
        return this.enumValue.get();
    }

    public ChildVisitResult visitChildren(CursorVisitor visitor)
    {
        return LibClang.INSTANCE.clang_visitChildren(this.self, (cursor, parent, data) -> visitor.apply(new Cursor(cursor), new Cursor(parent)), null);
    }

    public interface CursorVisitor extends BiFunction<Cursor, Cursor, ChildVisitResult>
    {
        @Override
        ChildVisitResult apply(Cursor cursor, Cursor parent);
    }

    public enum ChildVisitResult
    {
        /**
         * Terminates the cursor traversal.
         */
        BREAK,
        /**
         * Continues the cursor traversal with the next sibling of
         * the cursor just visited, without visiting its children.
         */
        CONTINUE,
        /**
         * Recursively traverse the children of this cursor, using
         * the same visitor and client data.
         */
        RECURSE;
    }
}
