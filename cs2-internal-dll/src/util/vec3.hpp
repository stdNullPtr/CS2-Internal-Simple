#pragma once
#include <ostream>

namespace util
{
    struct vec3
    {
        float x, y, z;

        vec3 operator+(const vec3& other) const
        {
            return {.x = x + other.x, .y = y + other.y, .z = z + other.z};
        }

        vec3 operator-(const vec3& other) const
        {
            return {.x = x - other.x, .y = y - other.y, .z = z - other.z};
        }

        friend std::ostream& operator<<(std::ostream& os, const vec3& vec)
        {
            os << "[" << vec.x << ", " << vec.y << ", " << vec.z << "]";
            return os;
        }

        friend std::wostream& operator<<(std::wostream& os, const vec3& vec)
        {
            os << "[" << vec.x << ", " << vec.y << ", " << vec.z << "]";
            return os;
        }
    };
}
