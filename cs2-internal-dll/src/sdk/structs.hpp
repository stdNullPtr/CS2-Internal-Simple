#pragma once
#include <cstdint>
#include "../util/vec3.hpp"

#pragma pack(push, 1)

namespace cheat::sdk
{
    class EntitySpottedState_t
    {
    public:
        char pad_0000[8]; //0x0000
        bool m_bSpotted; //0x0008
        char pad_0009[3]; //0x0009
        uint64_t m_bSpottedByMask; //0x000C
    }; //Size: 0x0014

    class C_CSPlayerPawn
    {
    public:
        char pad_0000[808]; //0x0000
        class CGameSceneNode* m_pGameSceneNode; //0x0328
        char pad_0330[16]; //0x0330
        int32_t m_iMaxHealth; //0x0340
        int32_t m_iHealth; //0x0344
        char pad_0348[155]; //0x0348
        uint8_t m_iTeamNum; //0x03E3
        char pad_03E4[2157]; //0x03E4
        bool m_bGlowing; //0x0C51
        char pad_0C52[94]; //0x0C52
        util::vec3 m_vecViewOffset; //0x0CB0
        char pad_0CBC[1324]; //0x0CBC
        void* m_pMovementServices; //0x11E8
        char pad_11F0[432]; //0x11F0
        class C_CSWeaponBase* m_pClippingWeapon; //0x13A0
        char pad_13A8[96]; //0x13A8
        float m_flFlashMaxAlpha; //0x1408
        float m_flFlashDuration; //0x140C
        char pad_1410[4032]; //0x1410
        EntitySpottedState_t m_entitySpottedState; //0x23D0
        char pad_23E4[4]; //0x23E4
        bool m_bIsScoped; //0x23E8
    }; //Size: 0x2424

    class CCSPlayerController
    {
    public:
        char pad_0000[1776]; //0x0000
        bool m_bIsLocalPlayerController; //0x06F0
        char pad_06F1[127]; //0x06F1
        char* m_sSanitizedPlayerName; //0x0770
        char pad_0778[148]; //0x0778
        uint64_t m_hPlayerPawn; //0x080C
    }; //Size: 0x1044

    class CModelState
    {
    public:
        char pad_0000[128]; //0x0000
        class Bone (*m_pBoneArray)[32]; //0x0080
    }; //Size: 0x0088

    class CGameSceneNode
    {
    public:
        char pad_0000[136]; //0x0000
        util::vec3 m_vecOrigin; //0x0088
        char pad_0094[220]; //0x0094
        CModelState m_modelState; //0x0170
    }; //Size: 0x01F8

    class C_CSWeaponBase
    {
    public:
        char pad_0000[16]; //0x0000
        class CEntityIdentity* m_pEntity; //0x0010
    }; //Size: 0x0018

    class CEntityIdentity
    {
    public:
        char pad_0000[32]; //0x0000
        char* m_designerName; //0x0020
    }; //Size: 0x0028

    class Bone
    {
    public:
        float _11; //0x0000
        float _12; //0x0004
        float _13; //0x0008
        float _14; //0x000C
        float _21; //0x0010
        float _22; //0x0014
        float _23; //0x0018
        float _24; //0x001C
    }; //Size: 0x0020
}

#pragma pack(pop)
