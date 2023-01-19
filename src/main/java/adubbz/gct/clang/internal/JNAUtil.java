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

import com.google.common.base.Preconditions;
import com.sun.jna.Structure;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public class JNAUtil
{
    public static <T extends Structure> T[] makeContiguousArray(T[] in)
    {
        Preconditions.checkNotNull(in);
        Preconditions.checkArgument(in.length > 0);
        T[] out = (T[])in[0].toArray(in.length);

        for (int i = 1; i < in.length; i++)
        {
            T inElement = in[i];
            T outElement = out[i];

            // Use reflection to copy fields, except those defined in Structure
            for (Class<?> clazz = in[0].getClass(); clazz != Structure.class; clazz = clazz.getSuperclass())
            {
                for (Field field : clazz.getDeclaredFields())
                {
                    var modifiers = field.getModifiers();

                    // Skip static fields
                    if (Modifier.isStatic(modifiers))
                        continue;

                    // Make the field accessible
                    field.setAccessible(true);

                    // Eliminate any final modifiers
                    if (Modifier.isFinal(modifiers))
                    {
                        try
                        {
                            var modifiersField = Field.class.getDeclaredField("modifiers");
                            modifiersField.setAccessible(true);
                            modifiersField.setInt(field, modifiers & ~Modifier.FINAL);
                        }
                        catch (NoSuchFieldException | IllegalAccessException e)
                        {
                            throw new RuntimeException(e);
                        }
                    }

                    // Set the field in the out element to that of the in element
                    try
                    {
                        field.set(outElement, field.get(inElement));
                    }
                    catch (IllegalAccessException e)
                    {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        return out;
    }
}
