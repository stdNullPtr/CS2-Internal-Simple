#pragma once
#include <iomanip>
#include <ostream>
#include <xor.hpp>

namespace util
{
    struct view_matrix
    {
        float m[4][4];

        const float* operator[](const int index) const
        {
            return m[index];
        }

        float* operator[](const int index)
        {
            return m[index];
        }

        friend std::wostream& operator<<(std::wostream& os, const view_matrix& matrix)
        {
            os << XORW(L"view_matrix:\n");
            for (int i{0}; i < 4; ++i)
            {
                os << L"[ ";
                for (int j{0}; j < 4; ++j)
                {
                    os << std::setw(10) << std::fixed << std::setprecision(3) << matrix[i][j] << L" ";
                }
                os << L"]\n";
            }
            return os;
        }
    };
}
