#pragma once
#include <iomanip>
#include <ostream>
#include <xor.hpp>

namespace util
{
    struct bone_matrix
    {
        float m[4][2];

        const float* operator[](const int index) const
        {
            return m[index];
        }

        float* operator[](const int index)
        {
            return m[index];
        }

        friend std::wostream& operator<<(std::wostream& os, const bone_matrix& matrix)
        {
            os << XORW(L"bone_matrix:\n");
            for (int i{0}; i < 4; ++i)
            {
                os << L"[ ";
                for (int j{0}; j < 2; ++j)
                {
                    os << std::setw(10) << std::fixed << std::setprecision(3) << matrix[i][j] << L" ";
                }
                os << L"]\n";
            }
            return os;
        }
    };
}
