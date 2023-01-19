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

import java.util.EnumSet;
import java.util.HashMap;

public enum TypeKind
{
    INVALID(0),
    UNEXPOSED(1),
    VOID(2),
    BOOL(3),
    CHAR_U(4),
    U_CHAR(5),
    CHAR16(6),
    CHAR32(7),
    U_SHORT(8),
    U_INT(9),
    U_LONG(10),
    U_LONG_LONG(11),
    U_INT128(12),
    S_CHAR(14),
    W_CHAR(15),
    SHORT(16),
    INT(17),
    LONG(18),
    LONG_LONG(19),
    INT128(20),
    FLOAT(21),
    DOUBLE(22),
    LONG_DOUBLE(23),
    NULL_PTR(24),
    OVERLOAD(25),
    DEPENDENT(26),
    OBJ_C_ID(27),
    OBJ_C_CLASS(28),
    OBJ_C_SEL(29),
    FLOAT128(30),
    HALF(31),
    FLOAT16(32),
    SHORT_ACCUM(33),
    ACCUM(34),
    LONG_ACCUM(35),
    U_SHORT_ACCUM(36),
    U_ACCUM(37),
    U_LONG_ACCUM(38),
    B_FLOAT16(39),
    IBM128(40),
    COMPLEX(100),
    POINTER(101),
    BLOCK_POINTER(102),
    L_VALUE_REFERENCE(103),
    R_VALUE_REFERENCE(104),
    RECORD(105),
    ENUM(106),
    TYPEDEF(107),
    OBJ_C_INTERFACE(108),
    OBJ_C_OBJECT_POINTER(109),
    FUNCTION_NO_PROTO(110),
    FUNCTION_PROTO(111),
    CONSTANT_ARRAY(112),
    VECTOR(113),
    INCOMPLETE_ARRAY(114),
    VARIABLE_ARRAY(115),
    DEPENDENT_SIZED_ARRAY(116),
    MEMBER_POINTER(117),
    AUTO(118),
    ELABORATED(119),
    PIPE(120),
    O_C_L_SAMPLER(157),
    O_C_L_EVENT(158),
    O_C_L_QUEUE(159),
    O_C_L_RESERVE_I_D(160),
    OBJ_C_OBJECT(161),
    OBJ_C_TYPE_PARAM(162),
    ATTRIBUTED(163),
    O_C_L_INTEL_SUBGROUP_A_V_C_MCE_PAYLOAD(164),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_PAYLOAD(165),
    O_C_L_INTEL_SUBGROUP_A_V_C_REF_PAYLOAD(166),
    O_C_L_INTEL_SUBGROUP_A_V_C_SIC_PAYLOAD(167),
    O_C_L_INTEL_SUBGROUP_A_V_C_MCE_RESULT(168),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_RESULT(169),
    O_C_L_INTEL_SUBGROUP_A_V_C_REF_RESULT(170),
    O_C_L_INTEL_SUBGROUP_A_V_C_SIC_RESULT(171),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_RESULT_SINGLE_REF_STREAMOUT(172),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_RESULT_DUAL_REF_STREAMOUT(173),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_SINGLE_REF_STREAMIN(174),
    O_C_L_INTEL_SUBGROUP_A_V_C_IME_DUAL_REF_STREAMIN(175),
    EXT_VECTOR(176),
    ATOMIC(177),
    B_T_F_TAG_ATTRIBUTED(178);

    private static HashMap<Integer, TypeKind> byValue = new HashMap<>();

    private final int value;

    TypeKind(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return this.value;
    }

    public static TypeKind fromInteger(int value)
    {
        if (!byValue.containsKey(value))
            throw new RuntimeException("Unknown TypeKind " + value);

        return byValue.get(value);
    }

    static
    {
        EnumSet.allOf(TypeKind.class).forEach(e -> byValue.put(e.value, e));
    }
}
