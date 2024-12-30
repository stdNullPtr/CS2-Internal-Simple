#pragma once
#include <ostream>

namespace util
{
    struct vec2
    {
        float x, y;

        [[nodiscard]] float distance_squared(const vec2& other) const
        {
            const float dx{x - other.x};
            const float dy{y - other.y};
            return dx * dx + dy * dy;
        }

        vec2 operator+(const vec2& other) const
        {
            return {.x = x + other.x, .y = y + other.y};
        }

        vec2 operator-(const vec2& other) const
        {
            return {.x = x - other.x, .y = y - other.y};
        }

        friend std::ostream& operator<<(std::ostream& os, const vec2& vec)
        {
            os << "[" << vec.x << ", " << vec.y << "]";
            return os;
        }

        friend std::wostream& operator<<(std::wostream& os, const vec2& vec)
        {
            os << L"[" << vec.x << L", " << vec.y << L"]";
            return os;
        }
    };
}
