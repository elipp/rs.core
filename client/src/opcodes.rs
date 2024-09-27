use lazy_static::lazy_static;
use nohash_hasher::IntMap;

macro_rules! opcode_as_tuple {
    ($name:ident) => {
        ($name, stringify!($name))
    };
}

lazy_static! {
    pub static ref OPCODE_NAME_MAP: IntMap<u16, &'static str> = IntMap::from_iter([
        opcode_as_tuple!(MSG_NULL_ACTION),
        opcode_as_tuple!(CMSG_BOOTME),
        opcode_as_tuple!(CMSG_DBLOOKUP),
        opcode_as_tuple!(SMSG_DBLOOKUP),
        opcode_as_tuple!(CMSG_QUERY_OBJECT_POSITION),
        opcode_as_tuple!(SMSG_QUERY_OBJECT_POSITION),
        opcode_as_tuple!(CMSG_QUERY_OBJECT_ROTATION),
        opcode_as_tuple!(SMSG_QUERY_OBJECT_ROTATION),
        opcode_as_tuple!(CMSG_WORLD_TELEPORT),
        opcode_as_tuple!(CMSG_TELEPORT_TO_UNIT),
        opcode_as_tuple!(CMSG_ZONE_MAP),
        opcode_as_tuple!(SMSG_ZONE_MAP),
        opcode_as_tuple!(CMSG_DEBUG_CHANGECELLZONE),
        opcode_as_tuple!(CMSG_MOVE_CHARACTER_CHEAT),
        opcode_as_tuple!(SMSG_MOVE_CHARACTER_CHEAT),
        opcode_as_tuple!(CMSG_RECHARGE),
        opcode_as_tuple!(CMSG_LEARN_SPELL),
        opcode_as_tuple!(CMSG_CREATEMONSTER),
        opcode_as_tuple!(CMSG_DESTROYMONSTER),
        opcode_as_tuple!(CMSG_CREATEITEM),
        opcode_as_tuple!(CMSG_CREATEGAMEOBJECT),
        opcode_as_tuple!(SMSG_CHECK_FOR_BOTS),
        opcode_as_tuple!(CMSG_MAKEMONSTERATTACKGUID),
        opcode_as_tuple!(CMSG_BOT_DETECTED2),
        opcode_as_tuple!(CMSG_FORCEACTION),
        opcode_as_tuple!(CMSG_FORCEACTIONONOTHER),
        opcode_as_tuple!(CMSG_FORCEACTIONSHOW),
        opcode_as_tuple!(SMSG_FORCEACTIONSHOW),
        opcode_as_tuple!(CMSG_PETGODMODE),
        opcode_as_tuple!(SMSG_PETGODMODE),
        opcode_as_tuple!(SMSG_REFER_A_FRIEND_EXPIRED),
        opcode_as_tuple!(CMSG_WEATHER_SPEED_CHEAT),
        opcode_as_tuple!(CMSG_UNDRESSPLAYER),
        opcode_as_tuple!(CMSG_BEASTMASTER),
        opcode_as_tuple!(CMSG_GODMODE),
        opcode_as_tuple!(SMSG_GODMODE),
        opcode_as_tuple!(CMSG_CHEAT_SETMONEY),
        opcode_as_tuple!(CMSG_LEVEL_CHEAT),
        opcode_as_tuple!(CMSG_PET_LEVEL_CHEAT),
        opcode_as_tuple!(CMSG_SET_WORLDSTATE),
        opcode_as_tuple!(CMSG_COOLDOWN_CHEAT),
        opcode_as_tuple!(CMSG_USE_SKILL_CHEAT),
        opcode_as_tuple!(CMSG_FLAG_QUEST),
        opcode_as_tuple!(CMSG_FLAG_QUEST_FINISH),
        opcode_as_tuple!(CMSG_CLEAR_QUEST),
        opcode_as_tuple!(CMSG_SEND_EVENT),
        opcode_as_tuple!(CMSG_DEBUG_AISTATE),
        opcode_as_tuple!(SMSG_DEBUG_AISTATE),
        opcode_as_tuple!(CMSG_DISABLE_PVP_CHEAT),
        opcode_as_tuple!(CMSG_ADVANCE_SPAWN_TIME),
        opcode_as_tuple!(SMSG_DESTRUCTIBLE_BUILDING_DAMAGE),
        opcode_as_tuple!(CMSG_AUTH_SRP6_BEGIN),
        opcode_as_tuple!(CMSG_AUTH_SRP6_PROOF),
        opcode_as_tuple!(CMSG_AUTH_SRP6_RECODE),
        opcode_as_tuple!(CMSG_CHAR_CREATE),
        opcode_as_tuple!(CMSG_CHAR_ENUM),
        opcode_as_tuple!(CMSG_CHAR_DELETE),
        opcode_as_tuple!(SMSG_AUTH_SRP6_RESPONSE),
        opcode_as_tuple!(SMSG_CHAR_CREATE),
        opcode_as_tuple!(SMSG_CHAR_ENUM),
        opcode_as_tuple!(SMSG_CHAR_DELETE),
        opcode_as_tuple!(CMSG_PLAYER_LOGIN),
        opcode_as_tuple!(SMSG_NEW_WORLD),
        opcode_as_tuple!(SMSG_TRANSFER_PENDING),
        opcode_as_tuple!(SMSG_TRANSFER_ABORTED),
        opcode_as_tuple!(SMSG_CHARACTER_LOGIN_FAILED),
        opcode_as_tuple!(SMSG_LOGIN_SETTIMESPEED),
        opcode_as_tuple!(SMSG_GAMETIME_UPDATE),
        opcode_as_tuple!(CMSG_GAMETIME_SET),
        opcode_as_tuple!(SMSG_GAMETIME_SET),
        opcode_as_tuple!(CMSG_GAMESPEED_SET),
        opcode_as_tuple!(SMSG_GAMESPEED_SET),
        opcode_as_tuple!(CMSG_SERVERTIME),
        opcode_as_tuple!(SMSG_SERVERTIME),
        opcode_as_tuple!(CMSG_PLAYER_LOGOUT),
        opcode_as_tuple!(CMSG_LOGOUT_REQUEST),
        opcode_as_tuple!(SMSG_LOGOUT_RESPONSE),
        opcode_as_tuple!(SMSG_LOGOUT_COMPLETE),
        opcode_as_tuple!(CMSG_LOGOUT_CANCEL),
        opcode_as_tuple!(SMSG_LOGOUT_CANCEL_ACK),
        opcode_as_tuple!(CMSG_NAME_QUERY),
        opcode_as_tuple!(SMSG_NAME_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_PET_NAME_QUERY),
        opcode_as_tuple!(SMSG_PET_NAME_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_GUILD_QUERY),
        opcode_as_tuple!(SMSG_GUILD_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_ITEM_QUERY_SINGLE),
        opcode_as_tuple!(CMSG_ITEM_QUERY_MULTIPLE),
        opcode_as_tuple!(SMSG_ITEM_QUERY_SINGLE_RESPONSE),
        opcode_as_tuple!(SMSG_ITEM_QUERY_MULTIPLE_RESPONSE),
        opcode_as_tuple!(CMSG_PAGE_TEXT_QUERY),
        opcode_as_tuple!(SMSG_PAGE_TEXT_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_QUEST_QUERY),
        opcode_as_tuple!(SMSG_QUEST_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_GAMEOBJECT_QUERY),
        opcode_as_tuple!(SMSG_GAMEOBJECT_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_CREATURE_QUERY),
        opcode_as_tuple!(SMSG_CREATURE_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_WHO),
        opcode_as_tuple!(SMSG_WHO),
        opcode_as_tuple!(CMSG_WHOIS),
        opcode_as_tuple!(SMSG_WHOIS),
        opcode_as_tuple!(CMSG_CONTACT_LIST),
        opcode_as_tuple!(SMSG_CONTACT_LIST),
        opcode_as_tuple!(SMSG_FRIEND_STATUS),
        opcode_as_tuple!(CMSG_ADD_FRIEND),
        opcode_as_tuple!(CMSG_DEL_FRIEND),
        opcode_as_tuple!(CMSG_SET_CONTACT_NOTES),
        opcode_as_tuple!(CMSG_ADD_IGNORE),
        opcode_as_tuple!(CMSG_DEL_IGNORE),
        opcode_as_tuple!(CMSG_GROUP_INVITE),
        opcode_as_tuple!(SMSG_GROUP_INVITE),
        opcode_as_tuple!(CMSG_GROUP_CANCEL),
        opcode_as_tuple!(SMSG_GROUP_CANCEL),
        opcode_as_tuple!(CMSG_GROUP_ACCEPT),
        opcode_as_tuple!(CMSG_GROUP_DECLINE),
        opcode_as_tuple!(SMSG_GROUP_DECLINE),
        opcode_as_tuple!(CMSG_GROUP_UNINVITE),
        opcode_as_tuple!(CMSG_GROUP_UNINVITE_GUID),
        opcode_as_tuple!(SMSG_GROUP_UNINVITE),
        opcode_as_tuple!(CMSG_GROUP_SET_LEADER),
        opcode_as_tuple!(SMSG_GROUP_SET_LEADER),
        opcode_as_tuple!(CMSG_LOOT_METHOD),
        opcode_as_tuple!(CMSG_GROUP_DISBAND),
        opcode_as_tuple!(SMSG_GROUP_DESTROYED),
        opcode_as_tuple!(SMSG_GROUP_LIST),
        opcode_as_tuple!(SMSG_PARTY_MEMBER_STATS),
        opcode_as_tuple!(SMSG_PARTY_COMMAND_RESULT),
        opcode_as_tuple!(UMSG_UPDATE_GROUP_MEMBERS),
        opcode_as_tuple!(CMSG_GUILD_CREATE),
        opcode_as_tuple!(CMSG_GUILD_INVITE),
        opcode_as_tuple!(SMSG_GUILD_INVITE),
        opcode_as_tuple!(CMSG_GUILD_ACCEPT),
        opcode_as_tuple!(CMSG_GUILD_DECLINE),
        opcode_as_tuple!(SMSG_GUILD_DECLINE),
        opcode_as_tuple!(CMSG_GUILD_INFO),
        opcode_as_tuple!(SMSG_GUILD_INFO),
        opcode_as_tuple!(CMSG_GUILD_ROSTER),
        opcode_as_tuple!(SMSG_GUILD_ROSTER),
        opcode_as_tuple!(CMSG_GUILD_PROMOTE),
        opcode_as_tuple!(CMSG_GUILD_DEMOTE),
        opcode_as_tuple!(CMSG_GUILD_LEAVE),
        opcode_as_tuple!(CMSG_GUILD_REMOVE),
        opcode_as_tuple!(CMSG_GUILD_DISBAND),
        opcode_as_tuple!(CMSG_GUILD_LEADER),
        opcode_as_tuple!(CMSG_GUILD_MOTD),
        opcode_as_tuple!(SMSG_GUILD_EVENT),
        opcode_as_tuple!(SMSG_GUILD_COMMAND_RESULT),
        opcode_as_tuple!(UMSG_UPDATE_GUILD),
        opcode_as_tuple!(CMSG_MESSAGECHAT),
        opcode_as_tuple!(SMSG_MESSAGECHAT),
        opcode_as_tuple!(CMSG_JOIN_CHANNEL),
        opcode_as_tuple!(CMSG_LEAVE_CHANNEL),
        opcode_as_tuple!(SMSG_CHANNEL_NOTIFY),
        opcode_as_tuple!(CMSG_CHANNEL_LIST),
        opcode_as_tuple!(SMSG_CHANNEL_LIST),
        opcode_as_tuple!(CMSG_CHANNEL_PASSWORD),
        opcode_as_tuple!(CMSG_CHANNEL_SET_OWNER),
        opcode_as_tuple!(CMSG_CHANNEL_OWNER),
        opcode_as_tuple!(CMSG_CHANNEL_MODERATOR),
        opcode_as_tuple!(CMSG_CHANNEL_UNMODERATOR),
        opcode_as_tuple!(CMSG_CHANNEL_MUTE),
        opcode_as_tuple!(CMSG_CHANNEL_UNMUTE),
        opcode_as_tuple!(CMSG_CHANNEL_INVITE),
        opcode_as_tuple!(CMSG_CHANNEL_KICK),
        opcode_as_tuple!(CMSG_CHANNEL_BAN),
        opcode_as_tuple!(CMSG_CHANNEL_UNBAN),
        opcode_as_tuple!(CMSG_CHANNEL_ANNOUNCEMENTS),
        opcode_as_tuple!(CMSG_CHANNEL_MODERATE),
        opcode_as_tuple!(SMSG_UPDATE_OBJECT),
        opcode_as_tuple!(SMSG_DESTROY_OBJECT),
        opcode_as_tuple!(CMSG_USE_ITEM),
        opcode_as_tuple!(CMSG_OPEN_ITEM),
        opcode_as_tuple!(CMSG_READ_ITEM),
        opcode_as_tuple!(SMSG_READ_ITEM_OK),
        opcode_as_tuple!(SMSG_READ_ITEM_FAILED),
        opcode_as_tuple!(SMSG_ITEM_COOLDOWN),
        opcode_as_tuple!(CMSG_GAMEOBJ_USE),
        opcode_as_tuple!(CMSG_DESTROY_ITEMS),
        opcode_as_tuple!(SMSG_GAMEOBJECT_CUSTOM_ANIM),
        opcode_as_tuple!(CMSG_AREATRIGGER),
        opcode_as_tuple!(MSG_MOVE_START_FORWARD),
        opcode_as_tuple!(MSG_MOVE_START_BACKWARD),
        opcode_as_tuple!(MSG_MOVE_STOP),
        opcode_as_tuple!(MSG_MOVE_START_STRAFE_LEFT),
        opcode_as_tuple!(MSG_MOVE_START_STRAFE_RIGHT),
        opcode_as_tuple!(MSG_MOVE_STOP_STRAFE),
        opcode_as_tuple!(MSG_MOVE_JUMP),
        opcode_as_tuple!(MSG_MOVE_START_TURN_LEFT),
        opcode_as_tuple!(MSG_MOVE_START_TURN_RIGHT),
        opcode_as_tuple!(MSG_MOVE_STOP_TURN),
        opcode_as_tuple!(MSG_MOVE_START_PITCH_UP),
        opcode_as_tuple!(MSG_MOVE_START_PITCH_DOWN),
        opcode_as_tuple!(MSG_MOVE_STOP_PITCH),
        opcode_as_tuple!(MSG_MOVE_SET_RUN_MODE),
        opcode_as_tuple!(MSG_MOVE_SET_WALK_MODE),
        opcode_as_tuple!(MSG_MOVE_TOGGLE_LOGGING),
        opcode_as_tuple!(MSG_MOVE_TELEPORT),
        opcode_as_tuple!(MSG_MOVE_TELEPORT_CHEAT),
        opcode_as_tuple!(MSG_MOVE_TELEPORT_ACK),
        opcode_as_tuple!(MSG_MOVE_TOGGLE_FALL_LOGGING),
        opcode_as_tuple!(MSG_MOVE_FALL_LAND),
        opcode_as_tuple!(MSG_MOVE_START_SWIM),
        opcode_as_tuple!(MSG_MOVE_STOP_SWIM),
        opcode_as_tuple!(MSG_MOVE_SET_RUN_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_RUN_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_RUN_BACK_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_WALK_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_WALK_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_SWIM_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_SWIM_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_SWIM_BACK_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_ALL_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_TURN_RATE_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_TURN_RATE),
        opcode_as_tuple!(MSG_MOVE_TOGGLE_COLLISION_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_FACING),
        opcode_as_tuple!(MSG_MOVE_SET_PITCH),
        opcode_as_tuple!(MSG_MOVE_WORLDPORT_ACK),
        opcode_as_tuple!(SMSG_MONSTER_MOVE),
        opcode_as_tuple!(SMSG_MOVE_WATER_WALK),
        opcode_as_tuple!(SMSG_MOVE_LAND_WALK),
        opcode_as_tuple!(CMSG_MOVE_CHARM_PORT_CHEAT),
        opcode_as_tuple!(CMSG_MOVE_SET_RAW_POSITION),
        opcode_as_tuple!(SMSG_FORCE_RUN_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_RUN_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_RUN_BACK_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_RUN_BACK_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_SWIM_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_SWIM_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_MOVE_ROOT),
        opcode_as_tuple!(CMSG_FORCE_MOVE_ROOT_ACK),
        opcode_as_tuple!(SMSG_FORCE_MOVE_UNROOT),
        opcode_as_tuple!(CMSG_FORCE_MOVE_UNROOT_ACK),
        opcode_as_tuple!(MSG_MOVE_ROOT),
        opcode_as_tuple!(MSG_MOVE_UNROOT),
        opcode_as_tuple!(MSG_MOVE_HEARTBEAT),
        opcode_as_tuple!(SMSG_MOVE_KNOCK_BACK),
        opcode_as_tuple!(CMSG_MOVE_KNOCK_BACK_ACK),
        opcode_as_tuple!(MSG_MOVE_KNOCK_BACK),
        opcode_as_tuple!(SMSG_MOVE_FEATHER_FALL),
        opcode_as_tuple!(SMSG_MOVE_NORMAL_FALL),
        opcode_as_tuple!(SMSG_MOVE_SET_HOVER),
        opcode_as_tuple!(SMSG_MOVE_UNSET_HOVER),
        opcode_as_tuple!(CMSG_MOVE_HOVER_ACK),
        opcode_as_tuple!(MSG_MOVE_HOVER),
        opcode_as_tuple!(CMSG_TRIGGER_CINEMATIC_CHEAT),
        opcode_as_tuple!(CMSG_OPENING_CINEMATIC),
        opcode_as_tuple!(SMSG_TRIGGER_CINEMATIC),
        opcode_as_tuple!(CMSG_NEXT_CINEMATIC_CAMERA),
        opcode_as_tuple!(CMSG_COMPLETE_CINEMATIC),
        opcode_as_tuple!(SMSG_TUTORIAL_FLAGS),
        opcode_as_tuple!(CMSG_TUTORIAL_FLAG),
        opcode_as_tuple!(CMSG_TUTORIAL_CLEAR),
        opcode_as_tuple!(CMSG_TUTORIAL_RESET),
        opcode_as_tuple!(CMSG_STANDSTATECHANGE),
        opcode_as_tuple!(CMSG_EMOTE),
        opcode_as_tuple!(SMSG_EMOTE),
        opcode_as_tuple!(CMSG_TEXT_EMOTE),
        opcode_as_tuple!(SMSG_TEXT_EMOTE),
        opcode_as_tuple!(CMSG_AUTOEQUIP_GROUND_ITEM),
        opcode_as_tuple!(CMSG_AUTOSTORE_GROUND_ITEM),
        opcode_as_tuple!(CMSG_AUTOSTORE_LOOT_ITEM),
        opcode_as_tuple!(CMSG_STORE_LOOT_IN_SLOT),
        opcode_as_tuple!(CMSG_AUTOEQUIP_ITEM),
        opcode_as_tuple!(CMSG_AUTOSTORE_BAG_ITEM),
        opcode_as_tuple!(CMSG_SWAP_ITEM),
        opcode_as_tuple!(CMSG_SWAP_INV_ITEM),
        opcode_as_tuple!(CMSG_SPLIT_ITEM),
        opcode_as_tuple!(CMSG_AUTOEQUIP_ITEM_SLOT),
        opcode_as_tuple!(CMSG_UNCLAIM_LICENSE),
        opcode_as_tuple!(CMSG_DESTROYITEM),
        opcode_as_tuple!(SMSG_INVENTORY_CHANGE_FAILURE),
        opcode_as_tuple!(SMSG_OPEN_CONTAINER),
        opcode_as_tuple!(CMSG_INSPECT),
        opcode_as_tuple!(SMSG_INSPECT_RESULTS_UPDATE),
        opcode_as_tuple!(CMSG_INITIATE_TRADE),
        opcode_as_tuple!(CMSG_BEGIN_TRADE),
        opcode_as_tuple!(CMSG_BUSY_TRADE),
        opcode_as_tuple!(CMSG_IGNORE_TRADE),
        opcode_as_tuple!(CMSG_ACCEPT_TRADE),
        opcode_as_tuple!(CMSG_UNACCEPT_TRADE),
        opcode_as_tuple!(CMSG_CANCEL_TRADE),
        opcode_as_tuple!(CMSG_SET_TRADE_ITEM),
        opcode_as_tuple!(CMSG_CLEAR_TRADE_ITEM),
        opcode_as_tuple!(CMSG_SET_TRADE_GOLD),
        opcode_as_tuple!(SMSG_TRADE_STATUS),
        opcode_as_tuple!(SMSG_TRADE_STATUS_EXTENDED),
        opcode_as_tuple!(SMSG_INITIALIZE_FACTIONS),
        opcode_as_tuple!(SMSG_SET_FACTION_VISIBLE),
        opcode_as_tuple!(SMSG_SET_FACTION_STANDING),
        opcode_as_tuple!(CMSG_SET_FACTION_ATWAR),
        opcode_as_tuple!(CMSG_SET_FACTION_CHEAT),
        opcode_as_tuple!(SMSG_SET_PROFICIENCY),
        opcode_as_tuple!(CMSG_SET_ACTION_BUTTON),
        opcode_as_tuple!(SMSG_ACTION_BUTTONS),
        opcode_as_tuple!(SMSG_INITIAL_SPELLS),
        opcode_as_tuple!(SMSG_LEARNED_SPELL),
        opcode_as_tuple!(SMSG_SUPERCEDED_SPELL),
        opcode_as_tuple!(CMSG_NEW_SPELL_SLOT),
        opcode_as_tuple!(CMSG_CAST_SPELL),
        opcode_as_tuple!(CMSG_CANCEL_CAST),
        opcode_as_tuple!(SMSG_CAST_FAILED),
        opcode_as_tuple!(SMSG_SPELL_START),
        opcode_as_tuple!(SMSG_SPELL_GO),
        opcode_as_tuple!(SMSG_SPELL_FAILURE),
        opcode_as_tuple!(SMSG_SPELL_COOLDOWN),
        opcode_as_tuple!(SMSG_COOLDOWN_EVENT),
        opcode_as_tuple!(CMSG_CANCEL_AURA),
        opcode_as_tuple!(SMSG_EQUIPMENT_SET_ID),
        opcode_as_tuple!(SMSG_PET_CAST_FAILED),
        opcode_as_tuple!(MSG_CHANNEL_START),
        opcode_as_tuple!(MSG_CHANNEL_UPDATE),
        opcode_as_tuple!(CMSG_CANCEL_CHANNELLING),
        opcode_as_tuple!(SMSG_AI_REACTION),
        opcode_as_tuple!(CMSG_SET_SELECTION),
        opcode_as_tuple!(CMSG_DELETEEQUIPMENT_SET),
        opcode_as_tuple!(CMSG_INSTANCE_LOCK_RESPONSE),
        opcode_as_tuple!(CMSG_DEBUG_PASSIVE_AURA),
        opcode_as_tuple!(CMSG_ATTACKSWING),
        opcode_as_tuple!(CMSG_ATTACKSTOP),
        opcode_as_tuple!(SMSG_ATTACKSTART),
        opcode_as_tuple!(SMSG_ATTACKSTOP),
        opcode_as_tuple!(SMSG_ATTACKSWING_NOTINRANGE),
        opcode_as_tuple!(SMSG_ATTACKSWING_BADFACING),
        opcode_as_tuple!(SMSG_PENDING_RAID_LOCK),
        opcode_as_tuple!(SMSG_ATTACKSWING_DEADTARGET),
        opcode_as_tuple!(SMSG_ATTACKSWING_CANT_ATTACK),
        opcode_as_tuple!(SMSG_ATTACKERSTATEUPDATE),
        opcode_as_tuple!(SMSG_BATTLEFIELD_PORT_DENIED),
        opcode_as_tuple!(CMSG_PERFORM_ACTION_SET),
        opcode_as_tuple!(SMSG_RESUME_CAST_BAR),
        opcode_as_tuple!(SMSG_CANCEL_COMBAT),
        opcode_as_tuple!(SMSG_SPELLBREAKLOG),
        opcode_as_tuple!(SMSG_SPELLHEALLOG),
        opcode_as_tuple!(SMSG_SPELLENERGIZELOG),
        opcode_as_tuple!(SMSG_BREAK_TARGET),
        opcode_as_tuple!(CMSG_SAVE_PLAYER),
        opcode_as_tuple!(CMSG_SETDEATHBINDPOINT),
        opcode_as_tuple!(SMSG_BINDPOINTUPDATE),
        opcode_as_tuple!(CMSG_GETDEATHBINDZONE),
        opcode_as_tuple!(SMSG_BINDZONEREPLY),
        opcode_as_tuple!(SMSG_PLAYERBOUND),
        opcode_as_tuple!(SMSG_CLIENT_CONTROL_UPDATE),
        opcode_as_tuple!(CMSG_REPOP_REQUEST),
        opcode_as_tuple!(SMSG_RESURRECT_REQUEST),
        opcode_as_tuple!(CMSG_RESURRECT_RESPONSE),
        opcode_as_tuple!(CMSG_LOOT),
        opcode_as_tuple!(CMSG_LOOT_MONEY),
        opcode_as_tuple!(CMSG_LOOT_RELEASE),
        opcode_as_tuple!(SMSG_LOOT_RESPONSE),
        opcode_as_tuple!(SMSG_LOOT_RELEASE_RESPONSE),
        opcode_as_tuple!(SMSG_LOOT_REMOVED),
        opcode_as_tuple!(SMSG_LOOT_MONEY_NOTIFY),
        opcode_as_tuple!(SMSG_LOOT_ITEM_NOTIFY),
        opcode_as_tuple!(SMSG_LOOT_CLEAR_MONEY),
        opcode_as_tuple!(SMSG_ITEM_PUSH_RESULT),
        opcode_as_tuple!(SMSG_DUEL_REQUESTED),
        opcode_as_tuple!(SMSG_DUEL_OUTOFBOUNDS),
        opcode_as_tuple!(SMSG_DUEL_INBOUNDS),
        opcode_as_tuple!(SMSG_DUEL_COMPLETE),
        opcode_as_tuple!(SMSG_DUEL_WINNER),
        opcode_as_tuple!(CMSG_DUEL_ACCEPTED),
        opcode_as_tuple!(CMSG_DUEL_CANCELLED),
        opcode_as_tuple!(SMSG_MOUNTRESULT),
        opcode_as_tuple!(SMSG_DISMOUNTRESULT),
        opcode_as_tuple!(SMSG_REMOVED_FROM_PVP_QUEUE),
        opcode_as_tuple!(CMSG_MOUNTSPECIAL_ANIM),
        opcode_as_tuple!(SMSG_MOUNTSPECIAL_ANIM),
        opcode_as_tuple!(SMSG_PET_TAME_FAILURE),
        opcode_as_tuple!(CMSG_PET_SET_ACTION),
        opcode_as_tuple!(CMSG_PET_ACTION),
        opcode_as_tuple!(CMSG_PET_ABANDON),
        opcode_as_tuple!(CMSG_PET_RENAME),
        opcode_as_tuple!(SMSG_PET_NAME_INVALID),
        opcode_as_tuple!(SMSG_PET_SPELLS),
        opcode_as_tuple!(SMSG_PET_MODE),
        opcode_as_tuple!(CMSG_GOSSIP_HELLO),
        opcode_as_tuple!(CMSG_GOSSIP_SELECT_OPTION),
        opcode_as_tuple!(SMSG_GOSSIP_MESSAGE),
        opcode_as_tuple!(SMSG_GOSSIP_COMPLETE),
        opcode_as_tuple!(CMSG_NPC_TEXT_QUERY),
        opcode_as_tuple!(SMSG_NPC_TEXT_UPDATE),
        opcode_as_tuple!(SMSG_NPC_WONT_TALK),
        opcode_as_tuple!(CMSG_QUESTGIVER_STATUS_QUERY),
        opcode_as_tuple!(SMSG_QUESTGIVER_STATUS),
        opcode_as_tuple!(CMSG_QUESTGIVER_HELLO),
        opcode_as_tuple!(SMSG_QUESTGIVER_QUEST_LIST),
        opcode_as_tuple!(CMSG_QUESTGIVER_QUERY_QUEST),
        opcode_as_tuple!(CMSG_QUESTGIVER_QUEST_AUTOLAUNCH),
        opcode_as_tuple!(SMSG_QUESTGIVER_QUEST_DETAILS),
        opcode_as_tuple!(CMSG_QUESTGIVER_ACCEPT_QUEST),
        opcode_as_tuple!(CMSG_QUESTGIVER_COMPLETE_QUEST),
        opcode_as_tuple!(SMSG_QUESTGIVER_REQUEST_ITEMS),
        opcode_as_tuple!(CMSG_QUESTGIVER_REQUEST_REWARD),
        opcode_as_tuple!(SMSG_QUESTGIVER_OFFER_REWARD),
        opcode_as_tuple!(CMSG_QUESTGIVER_CHOOSE_REWARD),
        opcode_as_tuple!(SMSG_QUESTGIVER_QUEST_INVALID),
        opcode_as_tuple!(CMSG_QUESTGIVER_CANCEL),
        opcode_as_tuple!(SMSG_QUESTGIVER_QUEST_COMPLETE),
        opcode_as_tuple!(SMSG_QUESTGIVER_QUEST_FAILED),
        opcode_as_tuple!(CMSG_QUESTLOG_SWAP_QUEST),
        opcode_as_tuple!(CMSG_QUESTLOG_REMOVE_QUEST),
        opcode_as_tuple!(SMSG_QUESTLOG_FULL),
        opcode_as_tuple!(SMSG_QUESTUPDATE_FAILED),
        opcode_as_tuple!(SMSG_QUESTUPDATE_FAILEDTIMER),
        opcode_as_tuple!(SMSG_QUESTUPDATE_COMPLETE),
        opcode_as_tuple!(SMSG_QUESTUPDATE_ADD_KILL),
        opcode_as_tuple!(SMSG_QUESTUPDATE_ADD_ITEM_OBSOLETE),
        opcode_as_tuple!(CMSG_QUEST_CONFIRM_ACCEPT),
        opcode_as_tuple!(SMSG_QUEST_CONFIRM_ACCEPT),
        opcode_as_tuple!(CMSG_PUSHQUESTTOPARTY),
        opcode_as_tuple!(CMSG_LIST_INVENTORY),
        opcode_as_tuple!(SMSG_LIST_INVENTORY),
        opcode_as_tuple!(CMSG_SELL_ITEM),
        opcode_as_tuple!(SMSG_SELL_ITEM),
        opcode_as_tuple!(CMSG_BUY_ITEM),
        opcode_as_tuple!(CMSG_BUY_ITEM_IN_SLOT),
        opcode_as_tuple!(SMSG_BUY_ITEM),
        opcode_as_tuple!(SMSG_BUY_FAILED),
        opcode_as_tuple!(CMSG_TAXICLEARALLNODES),
        opcode_as_tuple!(CMSG_TAXIENABLEALLNODES),
        opcode_as_tuple!(CMSG_TAXISHOWNODES),
        opcode_as_tuple!(SMSG_SHOWTAXINODES),
        opcode_as_tuple!(CMSG_TAXINODE_STATUS_QUERY),
        opcode_as_tuple!(SMSG_TAXINODE_STATUS),
        opcode_as_tuple!(CMSG_TAXIQUERYAVAILABLENODES),
        opcode_as_tuple!(CMSG_ACTIVATETAXI),
        opcode_as_tuple!(SMSG_ACTIVATETAXIREPLY),
        opcode_as_tuple!(SMSG_NEW_TAXI_PATH),
        opcode_as_tuple!(CMSG_TRAINER_LIST),
        opcode_as_tuple!(SMSG_TRAINER_LIST),
        opcode_as_tuple!(CMSG_TRAINER_BUY_SPELL),
        opcode_as_tuple!(SMSG_TRAINER_BUY_SUCCEEDED),
        opcode_as_tuple!(SMSG_TRAINER_BUY_FAILED),
        opcode_as_tuple!(CMSG_BINDER_ACTIVATE),
        opcode_as_tuple!(SMSG_PLAYERBINDERROR),
        opcode_as_tuple!(CMSG_BANKER_ACTIVATE),
        opcode_as_tuple!(SMSG_SHOW_BANK),
        opcode_as_tuple!(CMSG_BUY_BANK_SLOT),
        opcode_as_tuple!(SMSG_BUY_BANK_SLOT_RESULT),
        opcode_as_tuple!(CMSG_PETITION_SHOWLIST),
        opcode_as_tuple!(SMSG_PETITION_SHOWLIST),
        opcode_as_tuple!(CMSG_PETITION_BUY),
        opcode_as_tuple!(CMSG_PETITION_SHOW_SIGNATURES),
        opcode_as_tuple!(SMSG_PETITION_SHOW_SIGNATURES),
        opcode_as_tuple!(CMSG_PETITION_SIGN),
        opcode_as_tuple!(SMSG_PETITION_SIGN_RESULTS),
        opcode_as_tuple!(MSG_PETITION_DECLINE),
        opcode_as_tuple!(CMSG_OFFER_PETITION),
        opcode_as_tuple!(CMSG_TURN_IN_PETITION),
        opcode_as_tuple!(SMSG_TURN_IN_PETITION_RESULTS),
        opcode_as_tuple!(CMSG_PETITION_QUERY),
        opcode_as_tuple!(SMSG_PETITION_QUERY_RESPONSE),
        opcode_as_tuple!(SMSG_FISH_NOT_HOOKED),
        opcode_as_tuple!(SMSG_FISH_ESCAPED),
        opcode_as_tuple!(CMSG_BUG),
        opcode_as_tuple!(SMSG_NOTIFICATION),
        opcode_as_tuple!(CMSG_PLAYED_TIME),
        opcode_as_tuple!(SMSG_PLAYED_TIME),
        opcode_as_tuple!(CMSG_QUERY_TIME),
        opcode_as_tuple!(SMSG_QUERY_TIME_RESPONSE),
        opcode_as_tuple!(SMSG_LOG_XPGAIN),
        opcode_as_tuple!(SMSG_AURACASTLOG),
        opcode_as_tuple!(CMSG_RECLAIM_CORPSE),
        opcode_as_tuple!(CMSG_WRAP_ITEM),
        opcode_as_tuple!(SMSG_LEVELUP_INFO),
        opcode_as_tuple!(MSG_MINIMAP_PING),
        opcode_as_tuple!(SMSG_RESISTLOG),
        opcode_as_tuple!(SMSG_ENCHANTMENTLOG),
        opcode_as_tuple!(CMSG_SET_SKILL_CHEAT),
        opcode_as_tuple!(SMSG_START_MIRROR_TIMER),
        opcode_as_tuple!(SMSG_PAUSE_MIRROR_TIMER),
        opcode_as_tuple!(SMSG_STOP_MIRROR_TIMER),
        opcode_as_tuple!(CMSG_PING),
        opcode_as_tuple!(SMSG_PONG),
        opcode_as_tuple!(SMSG_CLEAR_COOLDOWN),
        opcode_as_tuple!(SMSG_GAMEOBJECT_PAGETEXT),
        opcode_as_tuple!(CMSG_SETSHEATHED),
        opcode_as_tuple!(SMSG_COOLDOWN_CHEAT),
        opcode_as_tuple!(SMSG_SPELL_DELAYED),
        opcode_as_tuple!(CMSG_QUEST_POI_QUERY),
        opcode_as_tuple!(SMSG_QUEST_POI_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_GHOST),
        opcode_as_tuple!(CMSG_GM_INVIS),
        opcode_as_tuple!(SMSG_INVALID_PROMOTION_CODE),
        opcode_as_tuple!(MSG_GM_BIND_OTHER),
        opcode_as_tuple!(MSG_GM_SUMMON),
        opcode_as_tuple!(SMSG_ITEM_TIME_UPDATE),
        opcode_as_tuple!(SMSG_ITEM_ENCHANT_TIME_UPDATE),
        opcode_as_tuple!(SMSG_AUTH_CHALLENGE),
        opcode_as_tuple!(CMSG_AUTH_SESSION),
        opcode_as_tuple!(SMSG_AUTH_RESPONSE),
        opcode_as_tuple!(MSG_GM_SHOWLABEL),
        opcode_as_tuple!(CMSG_PET_CAST_SPELL),
        opcode_as_tuple!(MSG_SAVE_GUILD_EMBLEM),
        opcode_as_tuple!(MSG_TABARDVENDOR_ACTIVATE),
        opcode_as_tuple!(SMSG_PLAY_SPELL_VISUAL),
        opcode_as_tuple!(CMSG_ZONEUPDATE),
        opcode_as_tuple!(SMSG_PARTYKILLLOG),
        opcode_as_tuple!(SMSG_COMPRESSED_UPDATE_OBJECT),
        opcode_as_tuple!(SMSG_PLAY_SPELL_IMPACT),
        opcode_as_tuple!(SMSG_EXPLORATION_EXPERIENCE),
        opcode_as_tuple!(CMSG_GM_SET_SECURITY_GROUP),
        opcode_as_tuple!(CMSG_GM_NUKE),
        opcode_as_tuple!(MSG_RANDOM_ROLL),
        opcode_as_tuple!(SMSG_ENVIRONMENTALDAMAGELOG),
        opcode_as_tuple!(CMSG_CHANGEPLAYER_DIFFICULTY),
        opcode_as_tuple!(SMSG_RWHOIS),
        opcode_as_tuple!(SMSG_LFG_PLAYER_REWARD),
        opcode_as_tuple!(SMSG_LFG_TELEPORT_DENIED),
        opcode_as_tuple!(CMSG_UNLEARN_SPELL),
        opcode_as_tuple!(CMSG_UNLEARN_SKILL),
        opcode_as_tuple!(SMSG_REMOVED_SPELL),
        opcode_as_tuple!(CMSG_DECHARGE),
        opcode_as_tuple!(CMSG_GMTICKET_CREATE),
        opcode_as_tuple!(SMSG_GMTICKET_CREATE),
        opcode_as_tuple!(CMSG_GMTICKET_UPDATETEXT),
        opcode_as_tuple!(SMSG_GMTICKET_UPDATETEXT),
        opcode_as_tuple!(SMSG_ACCOUNT_DATA_TIMES),
        opcode_as_tuple!(CMSG_REQUEST_ACCOUNT_DATA),
        opcode_as_tuple!(CMSG_UPDATE_ACCOUNT_DATA),
        opcode_as_tuple!(SMSG_UPDATE_ACCOUNT_DATA),
        opcode_as_tuple!(SMSG_CLEAR_FAR_SIGHT_IMMEDIATE),
        opcode_as_tuple!(SMSG_CHANGEPLAYER_DIFFICULTY_RESULT),
        opcode_as_tuple!(CMSG_GM_TEACH),
        opcode_as_tuple!(CMSG_GM_CREATE_ITEM_TARGET),
        opcode_as_tuple!(CMSG_GMTICKET_GETTICKET),
        opcode_as_tuple!(SMSG_GMTICKET_GETTICKET),
        opcode_as_tuple!(CMSG_UNLEARN_TALENTS),
        opcode_as_tuple!(SMSG_INSTANCE_ENCOUNTER),
        opcode_as_tuple!(SMSG_GAMEOBJECT_DESPAWN_ANIM),
        opcode_as_tuple!(MSG_CORPSE_QUERY),
        opcode_as_tuple!(CMSG_GMTICKET_DELETETICKET),
        opcode_as_tuple!(SMSG_GMTICKET_DELETETICKET),
        opcode_as_tuple!(SMSG_CHAT_WRONG_FACTION),
        opcode_as_tuple!(CMSG_GMTICKET_SYSTEMSTATUS),
        opcode_as_tuple!(SMSG_GMTICKET_SYSTEMSTATUS),
        opcode_as_tuple!(CMSG_SPIRIT_HEALER_ACTIVATE),
        opcode_as_tuple!(CMSG_SET_STAT_CHEAT),
        opcode_as_tuple!(SMSG_QUEST_FORCE_REMOVED),
        opcode_as_tuple!(CMSG_SKILL_BUY_STEP),
        opcode_as_tuple!(CMSG_SKILL_BUY_RANK),
        opcode_as_tuple!(CMSG_XP_CHEAT),
        opcode_as_tuple!(SMSG_SPIRIT_HEALER_CONFIRM),
        opcode_as_tuple!(CMSG_CHARACTER_POINT_CHEAT),
        opcode_as_tuple!(SMSG_GOSSIP_POI),
        opcode_as_tuple!(CMSG_CHAT_IGNORED),
        opcode_as_tuple!(CMSG_GM_VISION),
        opcode_as_tuple!(CMSG_SERVER_COMMAND),
        opcode_as_tuple!(CMSG_GM_SILENCE),
        opcode_as_tuple!(CMSG_GM_REVEALTO),
        opcode_as_tuple!(CMSG_GM_RESURRECT),
        opcode_as_tuple!(CMSG_GM_SUMMONMOB),
        opcode_as_tuple!(CMSG_GM_MOVECORPSE),
        opcode_as_tuple!(CMSG_GM_FREEZE),
        opcode_as_tuple!(CMSG_GM_UBERINVIS),
        opcode_as_tuple!(CMSG_GM_REQUEST_PLAYER_INFO),
        opcode_as_tuple!(SMSG_GM_PLAYER_INFO),
        opcode_as_tuple!(CMSG_GUILD_RANK),
        opcode_as_tuple!(CMSG_GUILD_ADD_RANK),
        opcode_as_tuple!(CMSG_GUILD_DEL_RANK),
        opcode_as_tuple!(CMSG_GUILD_SET_PUBLIC_NOTE),
        opcode_as_tuple!(CMSG_GUILD_SET_OFFICER_NOTE),
        opcode_as_tuple!(SMSG_LOGIN_VERIFY_WORLD),
        opcode_as_tuple!(CMSG_CLEAR_EXPLORATION),
        opcode_as_tuple!(CMSG_SEND_MAIL),
        opcode_as_tuple!(SMSG_SEND_MAIL_RESULT),
        opcode_as_tuple!(CMSG_GET_MAIL_LIST),
        opcode_as_tuple!(SMSG_MAIL_LIST_RESULT),
        opcode_as_tuple!(CMSG_BATTLEFIELD_LIST),
        opcode_as_tuple!(SMSG_BATTLEFIELD_LIST),
        opcode_as_tuple!(CMSG_BATTLEFIELD_JOIN),
        opcode_as_tuple!(SMSG_FORCE_SET_VEHICLE_REC_ID),
        opcode_as_tuple!(CMSG_SET_VEHICLE_REC_ID_ACK),
        opcode_as_tuple!(CMSG_TAXICLEARNODE),
        opcode_as_tuple!(CMSG_TAXIENABLENODE),
        opcode_as_tuple!(CMSG_ITEM_TEXT_QUERY),
        opcode_as_tuple!(SMSG_ITEM_TEXT_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_MAIL_TAKE_MONEY),
        opcode_as_tuple!(CMSG_MAIL_TAKE_ITEM),
        opcode_as_tuple!(CMSG_MAIL_MARK_AS_READ),
        opcode_as_tuple!(CMSG_MAIL_RETURN_TO_SENDER),
        opcode_as_tuple!(CMSG_MAIL_DELETE),
        opcode_as_tuple!(CMSG_MAIL_CREATE_TEXT_ITEM),
        opcode_as_tuple!(SMSG_SPELLLOGMISS),
        opcode_as_tuple!(SMSG_SPELLLOGEXECUTE),
        opcode_as_tuple!(SMSG_DEBUGAURAPROC),
        opcode_as_tuple!(SMSG_PERIODICAURALOG),
        opcode_as_tuple!(SMSG_SPELLDAMAGESHIELD),
        opcode_as_tuple!(SMSG_SPELLNONMELEEDAMAGELOG),
        opcode_as_tuple!(CMSG_LEARN_TALENT),
        opcode_as_tuple!(SMSG_RESURRECT_FAILED),
        opcode_as_tuple!(CMSG_TOGGLE_PVP),
        opcode_as_tuple!(SMSG_ZONE_UNDER_ATTACK),
        opcode_as_tuple!(MSG_AUCTION_HELLO),
        opcode_as_tuple!(CMSG_AUCTION_SELL_ITEM),
        opcode_as_tuple!(CMSG_AUCTION_REMOVE_ITEM),
        opcode_as_tuple!(CMSG_AUCTION_LIST_ITEMS),
        opcode_as_tuple!(CMSG_AUCTION_LIST_OWNER_ITEMS),
        opcode_as_tuple!(CMSG_AUCTION_PLACE_BID),
        opcode_as_tuple!(SMSG_AUCTION_COMMAND_RESULT),
        opcode_as_tuple!(SMSG_AUCTION_LIST_RESULT),
        opcode_as_tuple!(SMSG_AUCTION_OWNER_LIST_RESULT),
        opcode_as_tuple!(SMSG_AUCTION_BIDDER_NOTIFICATION),
        opcode_as_tuple!(SMSG_AUCTION_OWNER_NOTIFICATION),
        opcode_as_tuple!(SMSG_PROCRESIST),
        opcode_as_tuple!(SMSG_COMBAT_EVENT_FAILED),
        opcode_as_tuple!(SMSG_DISPEL_FAILED),
        opcode_as_tuple!(SMSG_SPELLORDAMAGE_IMMUNE),
        opcode_as_tuple!(CMSG_AUCTION_LIST_BIDDER_ITEMS),
        opcode_as_tuple!(SMSG_AUCTION_BIDDER_LIST_RESULT),
        opcode_as_tuple!(SMSG_SET_FLAT_SPELL_MODIFIER),
        opcode_as_tuple!(SMSG_SET_PCT_SPELL_MODIFIER),
        opcode_as_tuple!(CMSG_SET_AMMO),
        opcode_as_tuple!(SMSG_CORPSE_RECLAIM_DELAY),
        opcode_as_tuple!(CMSG_SET_ACTIVE_MOVER),
        opcode_as_tuple!(CMSG_PET_CANCEL_AURA),
        opcode_as_tuple!(CMSG_PLAYER_AI_CHEAT),
        opcode_as_tuple!(CMSG_CANCEL_AUTO_REPEAT_SPELL),
        opcode_as_tuple!(MSG_GM_ACCOUNT_ONLINE),
        opcode_as_tuple!(MSG_LIST_STABLED_PETS),
        opcode_as_tuple!(CMSG_STABLE_PET),
        opcode_as_tuple!(CMSG_UNSTABLE_PET),
        opcode_as_tuple!(CMSG_BUY_STABLE_SLOT),
        opcode_as_tuple!(SMSG_STABLE_RESULT),
        opcode_as_tuple!(CMSG_STABLE_REVIVE_PET),
        opcode_as_tuple!(CMSG_STABLE_SWAP_PET),
        opcode_as_tuple!(MSG_QUEST_PUSH_RESULT),
        opcode_as_tuple!(SMSG_PLAY_MUSIC),
        opcode_as_tuple!(SMSG_PLAY_OBJECT_SOUND),
        opcode_as_tuple!(CMSG_REQUEST_PET_INFO),
        opcode_as_tuple!(CMSG_FAR_SIGHT),
        opcode_as_tuple!(SMSG_SPELLDISPELLOG),
        opcode_as_tuple!(SMSG_DAMAGE_CALC_LOG),
        opcode_as_tuple!(CMSG_ENABLE_DAMAGE_LOG),
        opcode_as_tuple!(CMSG_GROUP_CHANGE_SUB_GROUP),
        opcode_as_tuple!(CMSG_REQUEST_PARTY_MEMBER_STATS),
        opcode_as_tuple!(CMSG_GROUP_SWAP_SUB_GROUP),
        opcode_as_tuple!(CMSG_RESET_FACTION_CHEAT),
        opcode_as_tuple!(CMSG_AUTOSTORE_BANK_ITEM),
        opcode_as_tuple!(CMSG_AUTOBANK_ITEM),
        opcode_as_tuple!(MSG_QUERY_NEXT_MAIL_TIME),
        opcode_as_tuple!(SMSG_RECEIVED_MAIL),
        opcode_as_tuple!(SMSG_RAID_GROUP_ONLY),
        opcode_as_tuple!(CMSG_SET_DURABILITY_CHEAT),
        opcode_as_tuple!(CMSG_SET_PVP_RANK_CHEAT),
        opcode_as_tuple!(CMSG_ADD_PVP_MEDAL_CHEAT),
        opcode_as_tuple!(CMSG_DEL_PVP_MEDAL_CHEAT),
        opcode_as_tuple!(CMSG_SET_PVP_TITLE),
        opcode_as_tuple!(SMSG_PVP_CREDIT),
        opcode_as_tuple!(SMSG_AUCTION_REMOVED_NOTIFICATION),
        opcode_as_tuple!(CMSG_GROUP_RAID_CONVERT),
        opcode_as_tuple!(CMSG_GROUP_ASSISTANT_LEADER),
        opcode_as_tuple!(CMSG_BUYBACK_ITEM),
        opcode_as_tuple!(SMSG_SERVER_MESSAGE),
        opcode_as_tuple!(CMSG_SET_SAVED_INSTANCE_EXTEND),
        opcode_as_tuple!(SMSG_LFG_OFFER_CONTINUE),
        opcode_as_tuple!(CMSG_TEST_DROP_RATE),
        opcode_as_tuple!(SMSG_TEST_DROP_RATE_RESULT),
        opcode_as_tuple!(CMSG_LFG_GET_STATUS),
        opcode_as_tuple!(SMSG_SHOW_MAILBOX),
        opcode_as_tuple!(SMSG_RESET_RANGED_COMBAT_TIMER),
        opcode_as_tuple!(SMSG_CHAT_NOT_IN_PARTY),
        opcode_as_tuple!(CMSG_GMTICKETSYSTEM_TOGGLE),
        opcode_as_tuple!(CMSG_CANCEL_GROWTH_AURA),
        opcode_as_tuple!(SMSG_CANCEL_AUTO_REPEAT),
        opcode_as_tuple!(SMSG_STANDSTATE_UPDATE),
        opcode_as_tuple!(SMSG_LOOT_ALL_PASSED),
        opcode_as_tuple!(SMSG_LOOT_ROLL_WON),
        opcode_as_tuple!(CMSG_LOOT_ROLL),
        opcode_as_tuple!(SMSG_LOOT_START_ROLL),
        opcode_as_tuple!(SMSG_LOOT_ROLL),
        opcode_as_tuple!(CMSG_LOOT_MASTER_GIVE),
        opcode_as_tuple!(SMSG_LOOT_MASTER_LIST),
        opcode_as_tuple!(SMSG_SET_FORCED_REACTIONS),
        opcode_as_tuple!(SMSG_SPELL_FAILED_OTHER),
        opcode_as_tuple!(SMSG_GAMEOBJECT_RESET_STATE),
        opcode_as_tuple!(CMSG_REPAIR_ITEM),
        opcode_as_tuple!(SMSG_CHAT_PLAYER_NOT_FOUND),
        opcode_as_tuple!(MSG_TALENT_WIPE_CONFIRM),
        opcode_as_tuple!(SMSG_SUMMON_REQUEST),
        opcode_as_tuple!(CMSG_SUMMON_RESPONSE),
        opcode_as_tuple!(MSG_DEV_SHOWLABEL),
        opcode_as_tuple!(SMSG_MONSTER_MOVE_TRANSPORT),
        opcode_as_tuple!(SMSG_PET_BROKEN),
        opcode_as_tuple!(MSG_MOVE_FEATHER_FALL),
        opcode_as_tuple!(MSG_MOVE_WATER_WALK),
        opcode_as_tuple!(CMSG_SERVER_BROADCAST),
        opcode_as_tuple!(CMSG_SELF_RES),
        opcode_as_tuple!(SMSG_FEIGN_DEATH_RESISTED),
        opcode_as_tuple!(CMSG_RUN_SCRIPT),
        opcode_as_tuple!(SMSG_SCRIPT_MESSAGE),
        opcode_as_tuple!(SMSG_DUEL_COUNTDOWN),
        opcode_as_tuple!(SMSG_AREA_TRIGGER_MESSAGE),
        opcode_as_tuple!(CMSG_SHOWING_HELM),
        opcode_as_tuple!(CMSG_SHOWING_CLOAK),
        opcode_as_tuple!(SMSG_ROLE_CHOSEN),
        opcode_as_tuple!(SMSG_PLAYER_SKINNED),
        opcode_as_tuple!(SMSG_DURABILITY_DAMAGE_DEATH),
        opcode_as_tuple!(CMSG_SET_EXPLORATION),
        opcode_as_tuple!(CMSG_SET_ACTIONBAR_TOGGLES),
        opcode_as_tuple!(UMSG_DELETE_GUILD_CHARTER),
        opcode_as_tuple!(MSG_PETITION_RENAME),
        opcode_as_tuple!(SMSG_INIT_WORLD_STATES),
        opcode_as_tuple!(SMSG_UPDATE_WORLD_STATE),
        opcode_as_tuple!(CMSG_ITEM_NAME_QUERY),
        opcode_as_tuple!(SMSG_ITEM_NAME_QUERY_RESPONSE),
        opcode_as_tuple!(SMSG_PET_ACTION_FEEDBACK),
        opcode_as_tuple!(CMSG_CHAR_RENAME),
        opcode_as_tuple!(SMSG_CHAR_RENAME),
        opcode_as_tuple!(CMSG_MOVE_SPLINE_DONE),
        opcode_as_tuple!(CMSG_MOVE_FALL_RESET),
        opcode_as_tuple!(SMSG_INSTANCE_SAVE_CREATED),
        opcode_as_tuple!(SMSG_RAID_INSTANCE_INFO),
        opcode_as_tuple!(CMSG_REQUEST_RAID_INFO),
        opcode_as_tuple!(CMSG_MOVE_TIME_SKIPPED),
        opcode_as_tuple!(CMSG_MOVE_FEATHER_FALL_ACK),
        opcode_as_tuple!(CMSG_MOVE_WATER_WALK_ACK),
        opcode_as_tuple!(CMSG_MOVE_NOT_ACTIVE_MOVER),
        opcode_as_tuple!(SMSG_PLAY_SOUND),
        opcode_as_tuple!(CMSG_BATTLEFIELD_STATUS),
        opcode_as_tuple!(SMSG_BATTLEFIELD_STATUS),
        opcode_as_tuple!(CMSG_BATTLEFIELD_PORT),
        opcode_as_tuple!(MSG_INSPECT_HONOR_STATS),
        opcode_as_tuple!(CMSG_BATTLEMASTER_HELLO),
        opcode_as_tuple!(CMSG_MOVE_START_SWIM_CHEAT),
        opcode_as_tuple!(CMSG_MOVE_STOP_SWIM_CHEAT),
        opcode_as_tuple!(SMSG_FORCE_WALK_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_WALK_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_SWIM_BACK_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_SWIM_BACK_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_TURN_RATE_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_TURN_RATE_CHANGE_ACK),
        opcode_as_tuple!(MSG_PVP_LOG_DATA),
        opcode_as_tuple!(CMSG_LEAVE_BATTLEFIELD),
        opcode_as_tuple!(CMSG_AREA_SPIRIT_HEALER_QUERY),
        opcode_as_tuple!(CMSG_AREA_SPIRIT_HEALER_QUEUE),
        opcode_as_tuple!(SMSG_AREA_SPIRIT_HEALER_TIME),
        opcode_as_tuple!(CMSG_GM_UNTEACH),
        opcode_as_tuple!(SMSG_WARDEN_DATA),
        opcode_as_tuple!(CMSG_WARDEN_DATA),
        opcode_as_tuple!(SMSG_GROUP_JOINED_BATTLEGROUND),
        opcode_as_tuple!(MSG_BATTLEGROUND_PLAYER_POSITIONS),
        opcode_as_tuple!(CMSG_PET_STOP_ATTACK),
        opcode_as_tuple!(SMSG_BINDER_CONFIRM),
        opcode_as_tuple!(SMSG_BATTLEGROUND_PLAYER_JOINED),
        opcode_as_tuple!(SMSG_BATTLEGROUND_PLAYER_LEFT),
        opcode_as_tuple!(CMSG_BATTLEMASTER_JOIN),
        opcode_as_tuple!(SMSG_ADDON_INFO),
        opcode_as_tuple!(CMSG_PET_UNLEARN),
        opcode_as_tuple!(SMSG_PET_UNLEARN_CONFIRM),
        opcode_as_tuple!(SMSG_PARTY_MEMBER_STATS_FULL),
        opcode_as_tuple!(CMSG_PET_SPELL_AUTOCAST),
        opcode_as_tuple!(SMSG_WEATHER),
        opcode_as_tuple!(SMSG_PLAY_TIME_WARNING),
        opcode_as_tuple!(SMSG_MINIGAME_SETUP),
        opcode_as_tuple!(SMSG_MINIGAME_STATE),
        opcode_as_tuple!(CMSG_MINIGAME_MOVE),
        opcode_as_tuple!(SMSG_MINIGAME_MOVE_FAILED),
        opcode_as_tuple!(SMSG_RAID_INSTANCE_MESSAGE),
        opcode_as_tuple!(SMSG_COMPRESSED_MOVES),
        opcode_as_tuple!(CMSG_GUILD_INFO_TEXT),
        opcode_as_tuple!(SMSG_CHAT_RESTRICTED),
        opcode_as_tuple!(SMSG_SPLINE_SET_RUN_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_RUN_BACK_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_SWIM_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_WALK_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_SWIM_BACK_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_TURN_RATE),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_UNROOT),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_FEATHER_FALL),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_NORMAL_FALL),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_SET_HOVER),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_UNSET_HOVER),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_WATER_WALK),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_LAND_WALK),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_START_SWIM),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_STOP_SWIM),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_SET_RUN_MODE),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_SET_WALK_MODE),
        opcode_as_tuple!(CMSG_GM_NUKE_ACCOUNT),
        opcode_as_tuple!(MSG_GM_DESTROY_CORPSE),
        opcode_as_tuple!(CMSG_GM_DESTROY_ONLINE_CORPSE),
        opcode_as_tuple!(CMSG_ACTIVATETAXIEXPRESS),
        opcode_as_tuple!(SMSG_SET_FACTION_ATWAR),
        opcode_as_tuple!(SMSG_GAMETIMEBIAS_SET),
        opcode_as_tuple!(CMSG_DEBUG_ACTIONS_START),
        opcode_as_tuple!(CMSG_DEBUG_ACTIONS_STOP),
        opcode_as_tuple!(CMSG_SET_FACTION_INACTIVE),
        opcode_as_tuple!(CMSG_SET_WATCHED_FACTION),
        opcode_as_tuple!(MSG_MOVE_TIME_SKIPPED),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_ROOT),
        opcode_as_tuple!(CMSG_SET_EXPLORATION_ALL),
        opcode_as_tuple!(SMSG_INVALIDATE_PLAYER),
        opcode_as_tuple!(CMSG_RESET_INSTANCES),
        opcode_as_tuple!(SMSG_INSTANCE_RESET),
        opcode_as_tuple!(SMSG_INSTANCE_RESET_FAILED),
        opcode_as_tuple!(SMSG_UPDATE_LAST_INSTANCE),
        opcode_as_tuple!(MSG_RAID_TARGET_UPDATE),
        opcode_as_tuple!(MSG_RAID_READY_CHECK),
        opcode_as_tuple!(CMSG_LUA_USAGE),
        opcode_as_tuple!(SMSG_PET_ACTION_SOUND),
        opcode_as_tuple!(SMSG_PET_DISMISS_SOUND),
        opcode_as_tuple!(SMSG_GHOSTEE_GONE),
        opcode_as_tuple!(CMSG_GM_UPDATE_TICKET_STATUS),
        opcode_as_tuple!(SMSG_GM_TICKET_STATUS_UPDATE),
        opcode_as_tuple!(MSG_SET_DUNGEON_DIFFICULTY),
        opcode_as_tuple!(CMSG_GMSURVEY_SUBMIT),
        opcode_as_tuple!(SMSG_UPDATE_INSTANCE_OWNERSHIP),
        opcode_as_tuple!(CMSG_IGNORE_KNOCKBACK_CHEAT),
        opcode_as_tuple!(SMSG_CHAT_PLAYER_AMBIGUOUS),
        opcode_as_tuple!(MSG_DELAY_GHOST_TELEPORT),
        opcode_as_tuple!(SMSG_SPELLINSTAKILLLOG),
        opcode_as_tuple!(SMSG_SPELL_UPDATE_CHAIN_TARGETS),
        opcode_as_tuple!(CMSG_CHAT_FILTERED),
        opcode_as_tuple!(SMSG_EXPECTED_SPAM_RECORDS),
        opcode_as_tuple!(SMSG_SPELLSTEALLOG),
        opcode_as_tuple!(CMSG_LOTTERY_QUERY_OBSOLETE),
        opcode_as_tuple!(SMSG_LOTTERY_QUERY_RESULT_OBSOLETE),
        opcode_as_tuple!(CMSG_BUY_LOTTERY_TICKET_OBSOLETE),
        opcode_as_tuple!(SMSG_LOTTERY_RESULT_OBSOLETE),
        opcode_as_tuple!(SMSG_CHARACTER_PROFILE),
        opcode_as_tuple!(SMSG_CHARACTER_PROFILE_REALM_CONNECTED),
        opcode_as_tuple!(SMSG_DEFENSE_MESSAGE),
        opcode_as_tuple!(SMSG_INSTANCE_DIFFICULTY),
        opcode_as_tuple!(MSG_GM_RESETINSTANCELIMIT),
        opcode_as_tuple!(SMSG_MOTD),
        opcode_as_tuple!(SMSG_MOVE_SET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY),
        opcode_as_tuple!(SMSG_MOVE_UNSET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY),
        opcode_as_tuple!(CMSG_MOVE_SET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY_ACK),
        opcode_as_tuple!(MSG_MOVE_START_SWIM_CHEAT),
        opcode_as_tuple!(MSG_MOVE_STOP_SWIM_CHEAT),
        opcode_as_tuple!(SMSG_MOVE_SET_CAN_FLY),
        opcode_as_tuple!(SMSG_MOVE_UNSET_CAN_FLY),
        opcode_as_tuple!(CMSG_MOVE_SET_CAN_FLY_ACK),
        opcode_as_tuple!(CMSG_MOVE_SET_FLY),
        opcode_as_tuple!(CMSG_SOCKET_GEMS),
        opcode_as_tuple!(CMSG_ARENA_TEAM_CREATE),
        opcode_as_tuple!(SMSG_ARENA_TEAM_COMMAND_RESULT),
        opcode_as_tuple!(MSG_MOVE_UPDATE_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY),
        opcode_as_tuple!(CMSG_ARENA_TEAM_QUERY),
        opcode_as_tuple!(SMSG_ARENA_TEAM_QUERY_RESPONSE),
        opcode_as_tuple!(CMSG_ARENA_TEAM_ROSTER),
        opcode_as_tuple!(SMSG_ARENA_TEAM_ROSTER),
        opcode_as_tuple!(CMSG_ARENA_TEAM_INVITE),
        opcode_as_tuple!(SMSG_ARENA_TEAM_INVITE),
        opcode_as_tuple!(CMSG_ARENA_TEAM_ACCEPT),
        opcode_as_tuple!(CMSG_ARENA_TEAM_DECLINE),
        opcode_as_tuple!(CMSG_ARENA_TEAM_LEAVE),
        opcode_as_tuple!(CMSG_ARENA_TEAM_REMOVE),
        opcode_as_tuple!(CMSG_ARENA_TEAM_DISBAND),
        opcode_as_tuple!(CMSG_ARENA_TEAM_LEADER),
        opcode_as_tuple!(SMSG_ARENA_TEAM_EVENT),
        opcode_as_tuple!(CMSG_BATTLEMASTER_JOIN_ARENA),
        opcode_as_tuple!(MSG_MOVE_START_ASCEND),
        opcode_as_tuple!(MSG_MOVE_STOP_ASCEND),
        opcode_as_tuple!(SMSG_ARENA_TEAM_STATS),
        opcode_as_tuple!(CMSG_LFG_JOIN),
        opcode_as_tuple!(CMSG_LFG_LEAVE),
        opcode_as_tuple!(CMSG_LFG_SEARCH_JOIN),
        opcode_as_tuple!(CMSG_LFG_SEARCH_LEAVE),
        opcode_as_tuple!(SMSG_LFG_SEARCH_RESULTS),
        opcode_as_tuple!(SMSG_LFG_PROPOSAL_UPDATE),
        opcode_as_tuple!(CMSG_LFG_PROPOSAL_RESPONSE),
        opcode_as_tuple!(SMSG_LFG_ROLE_CHECK_UPDATE),
        opcode_as_tuple!(SMSG_LFG_JOIN_RESULT),
        opcode_as_tuple!(SMSG_LFG_QUEUE_STATUS),
        opcode_as_tuple!(CMSG_SET_LFG_COMMENT),
        opcode_as_tuple!(SMSG_LFG_UPDATE_PLAYER),
        opcode_as_tuple!(SMSG_LFG_UPDATE_PARTY),
        opcode_as_tuple!(SMSG_LFG_UPDATE_SEARCH),
        opcode_as_tuple!(CMSG_LFG_SET_ROLES),
        opcode_as_tuple!(CMSG_LFG_SET_NEEDS),
        opcode_as_tuple!(CMSG_LFG_BOOT_PLAYER_VOTE),
        opcode_as_tuple!(SMSG_LFG_BOOT_PLAYER),
        opcode_as_tuple!(CMSG_LFG_GET_PLAYER_INFO),
        opcode_as_tuple!(SMSG_LFG_PLAYER_INFO),
        opcode_as_tuple!(CMSG_LFG_TELEPORT),
        opcode_as_tuple!(CMSG_LFG_GET_PARTY_INFO),
        opcode_as_tuple!(SMSG_LFG_PARTY_INFO),
        opcode_as_tuple!(SMSG_TITLE_EARNED),
        opcode_as_tuple!(CMSG_SET_TITLE),
        opcode_as_tuple!(CMSG_CANCEL_MOUNT_AURA),
        opcode_as_tuple!(SMSG_ARENA_ERROR),
        opcode_as_tuple!(MSG_INSPECT_ARENA_TEAMS),
        opcode_as_tuple!(SMSG_DEATH_RELEASE_LOC),
        opcode_as_tuple!(CMSG_CANCEL_TEMP_ENCHANTMENT),
        opcode_as_tuple!(SMSG_FORCED_DEATH_UPDATE),
        opcode_as_tuple!(CMSG_CHEAT_SET_HONOR_CURRENCY),
        opcode_as_tuple!(CMSG_CHEAT_SET_ARENA_CURRENCY),
        opcode_as_tuple!(MSG_MOVE_SET_FLIGHT_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_FLIGHT_SPEED),
        opcode_as_tuple!(MSG_MOVE_SET_FLIGHT_BACK_SPEED_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_FLIGHT_BACK_SPEED),
        opcode_as_tuple!(SMSG_FORCE_FLIGHT_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_FLIGHT_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_FORCE_FLIGHT_BACK_SPEED_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_FLIGHT_BACK_SPEED_CHANGE_ACK),
        opcode_as_tuple!(SMSG_SPLINE_SET_FLIGHT_SPEED),
        opcode_as_tuple!(SMSG_SPLINE_SET_FLIGHT_BACK_SPEED),
        opcode_as_tuple!(CMSG_MAELSTROM_INVALIDATE_CACHE),
        opcode_as_tuple!(SMSG_FLIGHT_SPLINE_SYNC),
        opcode_as_tuple!(CMSG_SET_TAXI_BENCHMARK_MODE),
        opcode_as_tuple!(SMSG_JOINED_BATTLEGROUND_QUEUE),
        opcode_as_tuple!(SMSG_REALM_SPLIT),
        opcode_as_tuple!(CMSG_REALM_SPLIT),
        opcode_as_tuple!(CMSG_MOVE_CHNG_TRANSPORT),
        opcode_as_tuple!(MSG_PARTY_ASSIGNMENT),
        opcode_as_tuple!(SMSG_OFFER_PETITION_ERROR),
        opcode_as_tuple!(SMSG_TIME_SYNC_REQ),
        opcode_as_tuple!(CMSG_TIME_SYNC_RESP),
        opcode_as_tuple!(CMSG_SEND_LOCAL_EVENT),
        opcode_as_tuple!(CMSG_SEND_GENERAL_TRIGGER),
        opcode_as_tuple!(CMSG_SEND_COMBAT_TRIGGER),
        opcode_as_tuple!(CMSG_MAELSTROM_GM_SENT_MAIL),
        opcode_as_tuple!(SMSG_RESET_FAILED_NOTIFY),
        opcode_as_tuple!(SMSG_REAL_GROUP_UPDATE),
        opcode_as_tuple!(SMSG_LFG_DISABLED),
        opcode_as_tuple!(CMSG_ACTIVE_PVP_CHEAT),
        opcode_as_tuple!(CMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY),
        opcode_as_tuple!(SMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY_RESPONSE),
        opcode_as_tuple!(SMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY_RESPONSE_WRITE_FILE),
        opcode_as_tuple!(SMSG_UPDATE_COMBO_POINTS),
        opcode_as_tuple!(SMSG_VOICE_SESSION_ROSTER_UPDATE),
        opcode_as_tuple!(SMSG_VOICE_SESSION_LEAVE),
        opcode_as_tuple!(SMSG_VOICE_SESSION_ADJUST_PRIORITY),
        opcode_as_tuple!(CMSG_VOICE_SET_TALKER_MUTED_REQUEST),
        opcode_as_tuple!(SMSG_VOICE_SET_TALKER_MUTED),
        opcode_as_tuple!(SMSG_INIT_EXTRA_AURA_INFO_OBSOLETE),
        opcode_as_tuple!(SMSG_SET_EXTRA_AURA_INFO_OBSOLETE),
        opcode_as_tuple!(SMSG_SET_EXTRA_AURA_INFO_NEED_UPDATE_OBSOLETE),
        opcode_as_tuple!(SMSG_CLEAR_EXTRA_AURA_INFO_OBSOLETE),
        opcode_as_tuple!(MSG_MOVE_START_DESCEND),
        opcode_as_tuple!(CMSG_IGNORE_REQUIREMENTS_CHEAT),
        opcode_as_tuple!(SMSG_IGNORE_REQUIREMENTS_CHEAT),
        opcode_as_tuple!(SMSG_SPELL_CHANCE_PROC_LOG),
        opcode_as_tuple!(CMSG_MOVE_SET_RUN_SPEED),
        opcode_as_tuple!(SMSG_DISMOUNT),
        opcode_as_tuple!(MSG_MOVE_UPDATE_CAN_FLY),
        opcode_as_tuple!(MSG_RAID_READY_CHECK_CONFIRM),
        opcode_as_tuple!(CMSG_VOICE_SESSION_ENABLE),
        opcode_as_tuple!(SMSG_VOICE_SESSION_ENABLE),
        opcode_as_tuple!(SMSG_VOICE_PARENTAL_CONTROLS),
        opcode_as_tuple!(CMSG_GM_WHISPER),
        opcode_as_tuple!(SMSG_GM_MESSAGECHAT),
        opcode_as_tuple!(MSG_GM_GEARRATING),
        opcode_as_tuple!(CMSG_COMMENTATOR_ENABLE),
        opcode_as_tuple!(SMSG_COMMENTATOR_STATE_CHANGED),
        opcode_as_tuple!(CMSG_COMMENTATOR_GET_MAP_INFO),
        opcode_as_tuple!(SMSG_COMMENTATOR_MAP_INFO),
        opcode_as_tuple!(CMSG_COMMENTATOR_GET_PLAYER_INFO),
        opcode_as_tuple!(SMSG_COMMENTATOR_GET_PLAYER_INFO),
        opcode_as_tuple!(SMSG_COMMENTATOR_PLAYER_INFO),
        opcode_as_tuple!(CMSG_COMMENTATOR_ENTER_INSTANCE),
        opcode_as_tuple!(CMSG_COMMENTATOR_EXIT_INSTANCE),
        opcode_as_tuple!(CMSG_COMMENTATOR_INSTANCE_COMMAND),
        opcode_as_tuple!(SMSG_CLEAR_TARGET),
        opcode_as_tuple!(CMSG_BOT_DETECTED),
        opcode_as_tuple!(SMSG_CROSSED_INEBRIATION_THRESHOLD),
        opcode_as_tuple!(CMSG_CHEAT_PLAYER_LOGIN),
        opcode_as_tuple!(CMSG_CHEAT_PLAYER_LOOKUP),
        opcode_as_tuple!(SMSG_CHEAT_PLAYER_LOOKUP),
        opcode_as_tuple!(SMSG_KICK_REASON),
        opcode_as_tuple!(MSG_RAID_READY_CHECK_FINISHED),
        opcode_as_tuple!(CMSG_COMPLAIN),
        opcode_as_tuple!(SMSG_COMPLAIN_RESULT),
        opcode_as_tuple!(SMSG_FEATURE_SYSTEM_STATUS),
        opcode_as_tuple!(CMSG_GM_SHOW_COMPLAINTS),
        opcode_as_tuple!(CMSG_GM_UNSQUELCH),
        opcode_as_tuple!(CMSG_CHANNEL_SILENCE_VOICE),
        opcode_as_tuple!(CMSG_CHANNEL_SILENCE_ALL),
        opcode_as_tuple!(CMSG_CHANNEL_UNSILENCE_VOICE),
        opcode_as_tuple!(CMSG_CHANNEL_UNSILENCE_ALL),
        opcode_as_tuple!(CMSG_TARGET_CAST),
        opcode_as_tuple!(CMSG_TARGET_SCRIPT_CAST),
        opcode_as_tuple!(CMSG_CHANNEL_DISPLAY_LIST),
        opcode_as_tuple!(CMSG_SET_ACTIVE_VOICE_CHANNEL),
        opcode_as_tuple!(CMSG_GET_CHANNEL_MEMBER_COUNT),
        opcode_as_tuple!(SMSG_CHANNEL_MEMBER_COUNT),
        opcode_as_tuple!(CMSG_CHANNEL_VOICE_ON),
        opcode_as_tuple!(CMSG_CHANNEL_VOICE_OFF),
        opcode_as_tuple!(CMSG_DEBUG_LIST_TARGETS),
        opcode_as_tuple!(SMSG_DEBUG_LIST_TARGETS),
        opcode_as_tuple!(SMSG_AVAILABLE_VOICE_CHANNEL),
        opcode_as_tuple!(CMSG_ADD_VOICE_IGNORE),
        opcode_as_tuple!(CMSG_DEL_VOICE_IGNORE),
        opcode_as_tuple!(CMSG_PARTY_SILENCE),
        opcode_as_tuple!(CMSG_PARTY_UNSILENCE),
        opcode_as_tuple!(MSG_NOTIFY_PARTY_SQUELCH),
        opcode_as_tuple!(SMSG_COMSAT_RECONNECT_TRY),
        opcode_as_tuple!(SMSG_COMSAT_DISCONNECT),
        opcode_as_tuple!(SMSG_COMSAT_CONNECT_FAIL),
        opcode_as_tuple!(SMSG_VOICE_CHAT_STATUS),
        opcode_as_tuple!(CMSG_REPORT_PVP_AFK),
        opcode_as_tuple!(SMSG_REPORT_PVP_AFK_RESULT),
        opcode_as_tuple!(CMSG_GUILD_BANKER_ACTIVATE),
        opcode_as_tuple!(CMSG_GUILD_BANK_QUERY_TAB),
        opcode_as_tuple!(SMSG_GUILD_BANK_LIST),
        opcode_as_tuple!(CMSG_GUILD_BANK_SWAP_ITEMS),
        opcode_as_tuple!(CMSG_GUILD_BANK_BUY_TAB),
        opcode_as_tuple!(CMSG_GUILD_BANK_UPDATE_TAB),
        opcode_as_tuple!(CMSG_GUILD_BANK_DEPOSIT_MONEY),
        opcode_as_tuple!(CMSG_GUILD_BANK_WITHDRAW_MONEY),
        opcode_as_tuple!(MSG_GUILD_BANK_LOG_QUERY),
        opcode_as_tuple!(CMSG_SET_CHANNEL_WATCH),
        opcode_as_tuple!(SMSG_USERLIST_ADD),
        opcode_as_tuple!(SMSG_USERLIST_REMOVE),
        opcode_as_tuple!(SMSG_USERLIST_UPDATE),
        opcode_as_tuple!(CMSG_CLEAR_CHANNEL_WATCH),
        opcode_as_tuple!(SMSG_INSPECT_RESULTS),
        opcode_as_tuple!(SMSG_GOGOGO_OBSOLETE),
        opcode_as_tuple!(SMSG_ECHO_PARTY_SQUELCH),
        opcode_as_tuple!(CMSG_SET_TITLE_SUFFIX),
        opcode_as_tuple!(CMSG_SPELLCLICK),
        opcode_as_tuple!(SMSG_LOOT_LIST),
        opcode_as_tuple!(CMSG_GM_CHARACTER_RESTORE),
        opcode_as_tuple!(CMSG_GM_CHARACTER_SAVE),
        opcode_as_tuple!(SMSG_VOICESESSION_FULL),
        opcode_as_tuple!(MSG_GUILD_PERMISSIONS),
        opcode_as_tuple!(MSG_GUILD_BANK_MONEY_WITHDRAWN),
        opcode_as_tuple!(MSG_GUILD_EVENT_LOG_QUERY),
        opcode_as_tuple!(CMSG_MAELSTROM_RENAME_GUILD),
        opcode_as_tuple!(CMSG_GET_MIRRORIMAGE_DATA),
        opcode_as_tuple!(SMSG_MIRRORIMAGE_DATA),
        opcode_as_tuple!(SMSG_FORCE_DISPLAY_UPDATE),
        opcode_as_tuple!(SMSG_SPELL_CHANCE_RESIST_PUSHBACK),
        opcode_as_tuple!(CMSG_IGNORE_DIMINISHING_RETURNS_CHEAT),
        opcode_as_tuple!(SMSG_IGNORE_DIMINISHING_RETURNS_CHEAT),
        opcode_as_tuple!(CMSG_KEEP_ALIVE),
        opcode_as_tuple!(SMSG_RAID_READY_CHECK_ERROR),
        opcode_as_tuple!(CMSG_OPT_OUT_OF_LOOT),
        opcode_as_tuple!(MSG_QUERY_GUILD_BANK_TEXT),
        opcode_as_tuple!(CMSG_SET_GUILD_BANK_TEXT),
        opcode_as_tuple!(CMSG_SET_GRANTABLE_LEVELS),
        opcode_as_tuple!(CMSG_GRANT_LEVEL),
        opcode_as_tuple!(CMSG_REFER_A_FRIEND),
        opcode_as_tuple!(MSG_GM_CHANGE_ARENA_RATING),
        opcode_as_tuple!(CMSG_DECLINE_CHANNEL_INVITE),
        opcode_as_tuple!(SMSG_GROUPACTION_THROTTLED),
        opcode_as_tuple!(SMSG_OVERRIDE_LIGHT),
        opcode_as_tuple!(SMSG_TOTEM_CREATED),
        opcode_as_tuple!(CMSG_TOTEM_DESTROYED),
        opcode_as_tuple!(CMSG_EXPIRE_RAID_INSTANCE),
        opcode_as_tuple!(CMSG_NO_SPELL_VARIANCE),
        opcode_as_tuple!(CMSG_QUESTGIVER_STATUS_MULTIPLE_QUERY),
        opcode_as_tuple!(SMSG_QUESTGIVER_STATUS_MULTIPLE),
        opcode_as_tuple!(CMSG_SET_PLAYER_DECLINED_NAMES),
        opcode_as_tuple!(SMSG_SET_PLAYER_DECLINED_NAMES_RESULT),
        opcode_as_tuple!(CMSG_QUERY_SERVER_BUCK_DATA),
        opcode_as_tuple!(CMSG_CLEAR_SERVER_BUCK_DATA),
        opcode_as_tuple!(SMSG_SERVER_BUCK_DATA),
        opcode_as_tuple!(SMSG_SEND_UNLEARN_SPELLS),
        opcode_as_tuple!(SMSG_PROPOSE_LEVEL_GRANT),
        opcode_as_tuple!(CMSG_ACCEPT_LEVEL_GRANT),
        opcode_as_tuple!(SMSG_REFER_A_FRIEND_FAILURE),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_SET_FLYING),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_UNSET_FLYING),
        opcode_as_tuple!(SMSG_SUMMON_CANCEL),
        opcode_as_tuple!(CMSG_CHANGE_PERSONAL_ARENA_RATING),
        opcode_as_tuple!(CMSG_ALTER_APPEARANCE),
        opcode_as_tuple!(SMSG_ENABLE_BARBER_SHOP),
        opcode_as_tuple!(SMSG_BARBER_SHOP_RESULT),
        opcode_as_tuple!(CMSG_CALENDAR_GET_CALENDAR),
        opcode_as_tuple!(CMSG_CALENDAR_GET_EVENT),
        opcode_as_tuple!(CMSG_CALENDAR_GUILD_FILTER),
        opcode_as_tuple!(CMSG_CALENDAR_ARENA_TEAM),
        opcode_as_tuple!(CMSG_CALENDAR_ADD_EVENT),
        opcode_as_tuple!(CMSG_CALENDAR_UPDATE_EVENT),
        opcode_as_tuple!(CMSG_CALENDAR_REMOVE_EVENT),
        opcode_as_tuple!(CMSG_CALENDAR_COPY_EVENT),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_INVITE),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_RSVP),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_REMOVE_INVITE),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_STATUS),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_MODERATOR_STATUS),
        opcode_as_tuple!(SMSG_CALENDAR_SEND_CALENDAR),
        opcode_as_tuple!(SMSG_CALENDAR_SEND_EVENT),
        opcode_as_tuple!(SMSG_CALENDAR_FILTER_GUILD),
        opcode_as_tuple!(SMSG_CALENDAR_ARENA_TEAM),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_REMOVED),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_STATUS),
        opcode_as_tuple!(SMSG_CALENDAR_COMMAND_RESULT),
        opcode_as_tuple!(SMSG_CALENDAR_RAID_LOCKOUT_ADDED),
        opcode_as_tuple!(SMSG_CALENDAR_RAID_LOCKOUT_REMOVED),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_ALERT),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_REMOVED_ALERT),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_STATUS_ALERT),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_REMOVED_ALERT),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_UPDATED_ALERT),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_MODERATOR_STATUS_ALERT),
        opcode_as_tuple!(CMSG_CALENDAR_COMPLAIN),
        opcode_as_tuple!(CMSG_CALENDAR_GET_NUM_PENDING),
        opcode_as_tuple!(SMSG_CALENDAR_SEND_NUM_PENDING),
        opcode_as_tuple!(CMSG_SAVE_DANCE),
        opcode_as_tuple!(SMSG_NOTIFY_DANCE),
        opcode_as_tuple!(CMSG_PLAY_DANCE),
        opcode_as_tuple!(SMSG_PLAY_DANCE),
        opcode_as_tuple!(CMSG_LOAD_DANCES),
        opcode_as_tuple!(CMSG_STOP_DANCE),
        opcode_as_tuple!(SMSG_STOP_DANCE),
        opcode_as_tuple!(CMSG_SYNC_DANCE),
        opcode_as_tuple!(CMSG_DANCE_QUERY),
        opcode_as_tuple!(SMSG_DANCE_QUERY_RESPONSE),
        opcode_as_tuple!(SMSG_INVALIDATE_DANCE),
        opcode_as_tuple!(CMSG_DELETE_DANCE),
        opcode_as_tuple!(SMSG_LEARNED_DANCE_MOVES),
        opcode_as_tuple!(CMSG_LEARN_DANCE_MOVE),
        opcode_as_tuple!(CMSG_UNLEARN_DANCE_MOVE),
        opcode_as_tuple!(CMSG_SET_RUNE_COUNT),
        opcode_as_tuple!(CMSG_SET_RUNE_COOLDOWN),
        opcode_as_tuple!(MSG_MOVE_SET_PITCH_RATE_CHEAT),
        opcode_as_tuple!(MSG_MOVE_SET_PITCH_RATE),
        opcode_as_tuple!(SMSG_FORCE_PITCH_RATE_CHANGE),
        opcode_as_tuple!(CMSG_FORCE_PITCH_RATE_CHANGE_ACK),
        opcode_as_tuple!(SMSG_SPLINE_SET_PITCH_RATE),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_INVITE_NOTES),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_NOTES),
        opcode_as_tuple!(SMSG_CALENDAR_EVENT_INVITE_NOTES_ALERT),
        opcode_as_tuple!(CMSG_UPDATE_MISSILE_TRAJECTORY),
        opcode_as_tuple!(SMSG_UPDATE_ACCOUNT_DATA_COMPLETE),
        opcode_as_tuple!(SMSG_TRIGGER_MOVIE),
        opcode_as_tuple!(CMSG_COMPLETE_MOVIE),
        opcode_as_tuple!(CMSG_SET_GLYPH_SLOT),
        opcode_as_tuple!(CMSG_SET_GLYPH),
        opcode_as_tuple!(SMSG_ACHIEVEMENT_EARNED),
        opcode_as_tuple!(SMSG_DYNAMIC_DROP_ROLL_RESULT),
        opcode_as_tuple!(SMSG_CRITERIA_UPDATE),
        opcode_as_tuple!(CMSG_QUERY_INSPECT_ACHIEVEMENTS),
        opcode_as_tuple!(SMSG_RESPOND_INSPECT_ACHIEVEMENTS),
        opcode_as_tuple!(CMSG_DISMISS_CONTROLLED_VEHICLE),
        opcode_as_tuple!(CMSG_COMPLETE_ACHIEVEMENT_CHEAT),
        opcode_as_tuple!(SMSG_QUESTUPDATE_ADD_PVP_KILL),
        opcode_as_tuple!(CMSG_SET_CRITERIA_CHEAT),
        opcode_as_tuple!(SMSG_CALENDAR_RAID_LOCKOUT_UPDATED),
        opcode_as_tuple!(CMSG_UNITANIMTIER_CHEAT),
        opcode_as_tuple!(CMSG_CHAR_CUSTOMIZE),
        opcode_as_tuple!(SMSG_CHAR_CUSTOMIZE),
        opcode_as_tuple!(SMSG_PET_RENAMEABLE),
        opcode_as_tuple!(CMSG_REQUEST_VEHICLE_EXIT),
        opcode_as_tuple!(CMSG_REQUEST_VEHICLE_PREV_SEAT),
        opcode_as_tuple!(CMSG_REQUEST_VEHICLE_NEXT_SEAT),
        opcode_as_tuple!(CMSG_REQUEST_VEHICLE_SWITCH_SEAT),
        opcode_as_tuple!(CMSG_PET_LEARN_TALENT),
        opcode_as_tuple!(CMSG_PET_UNLEARN_TALENTS),
        opcode_as_tuple!(SMSG_SET_PHASE_SHIFT),
        opcode_as_tuple!(SMSG_ALL_ACHIEVEMENT_DATA),
        opcode_as_tuple!(CMSG_FORCE_SAY_CHEAT),
        opcode_as_tuple!(SMSG_HEALTH_UPDATE),
        opcode_as_tuple!(SMSG_POWER_UPDATE),
        opcode_as_tuple!(CMSG_GAMEOBJ_REPORT_USE),
        opcode_as_tuple!(SMSG_HIGHEST_THREAT_UPDATE),
        opcode_as_tuple!(SMSG_THREAT_UPDATE),
        opcode_as_tuple!(SMSG_THREAT_REMOVE),
        opcode_as_tuple!(SMSG_THREAT_CLEAR),
        opcode_as_tuple!(SMSG_CONVERT_RUNE),
        opcode_as_tuple!(SMSG_RESYNC_RUNES),
        opcode_as_tuple!(SMSG_ADD_RUNE_POWER),
        opcode_as_tuple!(CMSG_START_QUEST),
        opcode_as_tuple!(CMSG_REMOVE_GLYPH),
        opcode_as_tuple!(CMSG_DUMP_OBJECTS),
        opcode_as_tuple!(SMSG_DUMP_OBJECTS_DATA),
        opcode_as_tuple!(CMSG_DISMISS_CRITTER),
        opcode_as_tuple!(SMSG_NOTIFY_DEST_LOC_SPELL_CAST),
        opcode_as_tuple!(CMSG_AUCTION_LIST_PENDING_SALES),
        opcode_as_tuple!(SMSG_AUCTION_LIST_PENDING_SALES),
        opcode_as_tuple!(SMSG_MODIFY_COOLDOWN),
        opcode_as_tuple!(SMSG_PET_UPDATE_COMBO_POINTS),
        opcode_as_tuple!(CMSG_ENABLETAXI),
        opcode_as_tuple!(SMSG_PRE_RESURRECT),
        opcode_as_tuple!(SMSG_AURA_UPDATE_ALL),
        opcode_as_tuple!(SMSG_AURA_UPDATE),
        opcode_as_tuple!(CMSG_FLOOD_GRACE_CHEAT),
        opcode_as_tuple!(SMSG_SERVER_FIRST_ACHIEVEMENT),
        opcode_as_tuple!(SMSG_PET_LEARNED_SPELL),
        opcode_as_tuple!(SMSG_PET_REMOVED_SPELL),
        opcode_as_tuple!(CMSG_CHANGE_SEATS_ON_CONTROLLED_VEHICLE),
        opcode_as_tuple!(CMSG_HEARTH_AND_RESURRECT),
        opcode_as_tuple!(SMSG_ON_CANCEL_EXPECTED_RIDE_VEHICLE_AURA),
        opcode_as_tuple!(SMSG_CRITERIA_DELETED),
        opcode_as_tuple!(SMSG_ACHIEVEMENT_DELETED),
        opcode_as_tuple!(CMSG_SERVER_INFO_QUERY),
        opcode_as_tuple!(SMSG_SERVER_INFO_RESPONSE),
        opcode_as_tuple!(CMSG_CHECK_LOGIN_CRITERIA),
        opcode_as_tuple!(SMSG_SERVER_BUCK_DATA_START),
        opcode_as_tuple!(CMSG_SET_BREATH),
        opcode_as_tuple!(CMSG_QUERY_VEHICLE_STATUS),
        opcode_as_tuple!(SMSG_BATTLEGROUND_INFO_THROTTLED),
        opcode_as_tuple!(SMSG_SET_VEHICLE_REC_ID),
        opcode_as_tuple!(CMSG_RIDE_VEHICLE_INTERACT),
        opcode_as_tuple!(CMSG_CONTROLLER_EJECT_PASSENGER),
        opcode_as_tuple!(SMSG_PET_GUIDS),
        opcode_as_tuple!(SMSG_CLIENTCACHE_VERSION),
        opcode_as_tuple!(CMSG_CHANGE_GDF_ARENA_RATING),
        opcode_as_tuple!(CMSG_SET_ARENA_TEAM_RATING_BY_INDEX),
        opcode_as_tuple!(CMSG_SET_ARENA_TEAM_WEEKLY_GAMES),
        opcode_as_tuple!(CMSG_SET_ARENA_TEAM_SEASON_GAMES),
        opcode_as_tuple!(CMSG_SET_ARENA_MEMBER_WEEKLY_GAMES),
        opcode_as_tuple!(CMSG_SET_ARENA_MEMBER_SEASON_GAMES),
        opcode_as_tuple!(SMSG_SET_ITEM_PURCHASE_DATA),
        opcode_as_tuple!(CMSG_GET_ITEM_PURCHASE_DATA),
        opcode_as_tuple!(CMSG_ITEM_PURCHASE_REFUND),
        opcode_as_tuple!(SMSG_ITEM_PURCHASE_REFUND_RESULT),
        opcode_as_tuple!(CMSG_CORPSE_TRANSPORT_QUERY),
        opcode_as_tuple!(SMSG_CORPSE_TRANSPORT_QUERY),
        opcode_as_tuple!(CMSG_UNUSED5),
        opcode_as_tuple!(CMSG_UNUSED6),
        opcode_as_tuple!(CMSG_CALENDAR_EVENT_SIGNUP),
        opcode_as_tuple!(SMSG_CALENDAR_CLEAR_PENDING_ACTION),
        opcode_as_tuple!(SMSG_LOAD_EQUIPMENT_SET),
        opcode_as_tuple!(CMSG_SAVE_EQUIPMENT_SET),
        opcode_as_tuple!(CMSG_ON_MISSILE_TRAJECTORY_COLLISION),
        opcode_as_tuple!(SMSG_NOTIFY_MISSILE_TRAJECTORY_COLLISION),
        opcode_as_tuple!(SMSG_TALENT_UPDATE),
        opcode_as_tuple!(CMSG_LEARN_TALENT_GROUP),
        opcode_as_tuple!(CMSG_PET_LEARN_TALENT_GROUP),
        opcode_as_tuple!(CMSG_SET_ACTIVE_TALENT_GROUP_OBSOLETE),
        opcode_as_tuple!(CMSG_GM_GRANT_ACHIEVEMENT),
        opcode_as_tuple!(CMSG_GM_REMOVE_ACHIEVEMENT),
        opcode_as_tuple!(CMSG_GM_SET_CRITERIA_FOR_PLAYER),
        opcode_as_tuple!(SMSG_DESTROY_ARENA_UNIT),
        opcode_as_tuple!(SMSG_ARENA_TEAM_CHANGE_FAILED),
        opcode_as_tuple!(CMSG_PROFILEDATA_REQUEST),
        opcode_as_tuple!(SMSG_PROFILEDATA_RESPONSE),
        opcode_as_tuple!(CMSG_START_BATTLEFIELD_CHEAT),
        opcode_as_tuple!(CMSG_END_BATTLEFIELD_CHEAT),
        opcode_as_tuple!(SMSG_COMPOUND_MOVE),
        opcode_as_tuple!(SMSG_MOVE_GRAVITY_DISABLE),
        opcode_as_tuple!(CMSG_MOVE_GRAVITY_DISABLE_ACK),
        opcode_as_tuple!(SMSG_MOVE_GRAVITY_ENABLE),
        opcode_as_tuple!(CMSG_MOVE_GRAVITY_ENABLE_ACK),
        opcode_as_tuple!(MSG_MOVE_GRAVITY_CHNG),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_GRAVITY_DISABLE),
        opcode_as_tuple!(SMSG_SPLINE_MOVE_GRAVITY_ENABLE),
        opcode_as_tuple!(CMSG_USE_EQUIPMENT_SET),
        opcode_as_tuple!(SMSG_USE_EQUIPMENT_SET_RESULT),
        opcode_as_tuple!(CMSG_FORCE_ANIM),
        opcode_as_tuple!(SMSG_FORCE_ANIM),
        opcode_as_tuple!(CMSG_CHAR_FACTION_CHANGE),
        opcode_as_tuple!(SMSG_CHAR_FACTION_CHANGE),
        opcode_as_tuple!(CMSG_PVP_QUEUE_STATS_REQUEST),
        opcode_as_tuple!(SMSG_PVP_QUEUE_STATS),
        opcode_as_tuple!(CMSG_SET_PAID_SERVICE_CHEAT),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_ENTRY_INVITE),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_ENTRY_INVITE_RESPONSE),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_ENTERING),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_QUEUE_INVITE),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_QUEUE_INVITE_RESPONSE),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_QUEUE_REQUEST),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_QUEUE_REQUEST_RESPONSE),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_EJECT_PENDING),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_EJECTED),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_EXIT_REQUEST),
        opcode_as_tuple!(SMSG_BATTLEFIELD_MANAGER_STATE_CHANGED),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_ADVANCE_STATE),
        opcode_as_tuple!(CMSG_BATTLEFIELD_MANAGER_SET_NEXT_TRANSITION_TIME),
        opcode_as_tuple!(MSG_SET_RAID_DIFFICULTY),
        opcode_as_tuple!(CMSG_XPGAIN),
        opcode_as_tuple!(SMSG_XPGAIN),
        opcode_as_tuple!(SMSG_GMTICKET_RESPONSE_ERROR),
        opcode_as_tuple!(SMSG_GMTICKET_GET_RESPONSE),
        opcode_as_tuple!(CMSG_GMTICKET_RESOLVE_RESPONSE),
        opcode_as_tuple!(SMSG_GMTICKET_RESOLVE_RESPONSE),
        opcode_as_tuple!(SMSG_GMTICKET_CREATE_RESPONSE_TICKET),
        opcode_as_tuple!(CMSG_GM_CREATE_TICKET_RESPONSE),
        opcode_as_tuple!(CMSG_SERVERINFO),
        opcode_as_tuple!(SMSG_SERVERINFO),
        opcode_as_tuple!(CMSG_UI_TIME_REQUEST),
        opcode_as_tuple!(SMSG_UI_TIME),
        opcode_as_tuple!(CMSG_CHAR_RACE_CHANGE),
        opcode_as_tuple!(MSG_VIEW_PHASE_SHIFT),
        opcode_as_tuple!(SMSG_TALENTS_INVOLUNTARILY_RESET),
        opcode_as_tuple!(CMSG_DEBUG_SERVER_GEO),
        opcode_as_tuple!(SMSG_DEBUG_SERVER_GEO),
        opcode_as_tuple!(SMSG_LOOT_UPDATE),
        opcode_as_tuple!(UMSG_UPDATE_GROUP_INFO),
        opcode_as_tuple!(CMSG_READY_FOR_ACCOUNT_DATA_TIMES),
        opcode_as_tuple!(CMSG_QUERY_GET_ALL_QUESTS),
        opcode_as_tuple!(SMSG_ALL_QUESTS_COMPLETED),
        opcode_as_tuple!(CMSG_GMLAGREPORT_SUBMIT),
        opcode_as_tuple!(CMSG_AFK_MONITOR_INFO_REQUEST),
        opcode_as_tuple!(SMSG_AFK_MONITOR_INFO_RESPONSE),
        opcode_as_tuple!(CMSG_AFK_MONITOR_INFO_CLEAR),
        opcode_as_tuple!(SMSG_AREA_TRIGGER_NO_CORPSE),
        opcode_as_tuple!(CMSG_GM_NUKE_CHARACTER),
        opcode_as_tuple!(CMSG_LOW_LEVEL_RAID),
        opcode_as_tuple!(CMSG_LOW_LEVEL_RAID_USER),
        opcode_as_tuple!(SMSG_CAMERA_SHAKE),
        opcode_as_tuple!(SMSG_SOCKET_GEMS),
        opcode_as_tuple!(CMSG_SET_CHARACTER_MODEL),
        opcode_as_tuple!(SMSG_CONNECT_TO),
        opcode_as_tuple!(CMSG_CONNECT_TO_FAILED),
        opcode_as_tuple!(SMSG_SUSPEND_COMMS),
        opcode_as_tuple!(CMSG_SUSPEND_COMMS_ACK),
        opcode_as_tuple!(SMSG_RESUME_COMMS),
        opcode_as_tuple!(CMSG_AUTH_CONTINUED_SESSION),
        opcode_as_tuple!(CMSG_DROP_NEW_CONNECTION),
        opcode_as_tuple!(SMSG_SEND_ALL_COMBAT_LOG),
        opcode_as_tuple!(SMSG_OPEN_LFG_DUNGEON_FINDER),
        opcode_as_tuple!(SMSG_MOVE_SET_COLLISION_HGT),
        opcode_as_tuple!(CMSG_MOVE_SET_COLLISION_HGT_ACK),
        opcode_as_tuple!(MSG_MOVE_SET_COLLISION_HGT),
        opcode_as_tuple!(CMSG_CLEAR_RANDOM_BG_WIN_TIME),
        opcode_as_tuple!(CMSG_CLEAR_HOLIDAY_BG_WIN_TIME),
        opcode_as_tuple!(CMSG_COMMENTATOR_SKIRMISH_QUEUE_COMMAND),
        opcode_as_tuple!(SMSG_COMMENTATOR_SKIRMISH_QUEUE_RESULT1),
        opcode_as_tuple!(SMSG_COMMENTATOR_SKIRMISH_QUEUE_RESULT2),
        opcode_as_tuple!(SMSG_COMPRESSED_UNKNOWN_1310),
        opcode_as_tuple!(NUM_MSG_TYPES),
    ]);
}

pub const MSG_NULL_ACTION: u16 = 0x000;
pub const CMSG_BOOTME: u16 = 0x001;
pub const CMSG_DBLOOKUP: u16 = 0x002;
pub const SMSG_DBLOOKUP: u16 = 0x003;
pub const CMSG_QUERY_OBJECT_POSITION: u16 = 0x004;
pub const SMSG_QUERY_OBJECT_POSITION: u16 = 0x005;
pub const CMSG_QUERY_OBJECT_ROTATION: u16 = 0x006;
pub const SMSG_QUERY_OBJECT_ROTATION: u16 = 0x007;
pub const CMSG_WORLD_TELEPORT: u16 = 0x008;
pub const CMSG_TELEPORT_TO_UNIT: u16 = 0x009;
pub const CMSG_ZONE_MAP: u16 = 0x00A;
pub const SMSG_ZONE_MAP: u16 = 0x00B;
pub const CMSG_DEBUG_CHANGECELLZONE: u16 = 0x00C;
pub const CMSG_MOVE_CHARACTER_CHEAT: u16 = 0x00D;
pub const SMSG_MOVE_CHARACTER_CHEAT: u16 = 0x00E;
pub const CMSG_RECHARGE: u16 = 0x00F;
pub const CMSG_LEARN_SPELL: u16 = 0x010;
pub const CMSG_CREATEMONSTER: u16 = 0x011;
pub const CMSG_DESTROYMONSTER: u16 = 0x012;
pub const CMSG_CREATEITEM: u16 = 0x013;
pub const CMSG_CREATEGAMEOBJECT: u16 = 0x014;
pub const SMSG_CHECK_FOR_BOTS: u16 = 0x015;
pub const CMSG_MAKEMONSTERATTACKGUID: u16 = 0x016;
pub const CMSG_BOT_DETECTED2: u16 = 0x017;
pub const CMSG_FORCEACTION: u16 = 0x018;
pub const CMSG_FORCEACTIONONOTHER: u16 = 0x019;
pub const CMSG_FORCEACTIONSHOW: u16 = 0x01A;
pub const SMSG_FORCEACTIONSHOW: u16 = 0x01B;
pub const CMSG_PETGODMODE: u16 = 0x01C;
pub const SMSG_PETGODMODE: u16 = 0x01D;
pub const SMSG_REFER_A_FRIEND_EXPIRED: u16 = 0x01E;
pub const CMSG_WEATHER_SPEED_CHEAT: u16 = 0x01F;
pub const CMSG_UNDRESSPLAYER: u16 = 0x020;
pub const CMSG_BEASTMASTER: u16 = 0x021;
pub const CMSG_GODMODE: u16 = 0x022;
pub const SMSG_GODMODE: u16 = 0x023;
pub const CMSG_CHEAT_SETMONEY: u16 = 0x024;
pub const CMSG_LEVEL_CHEAT: u16 = 0x025;
pub const CMSG_PET_LEVEL_CHEAT: u16 = 0x026;
pub const CMSG_SET_WORLDSTATE: u16 = 0x027;
pub const CMSG_COOLDOWN_CHEAT: u16 = 0x028;
pub const CMSG_USE_SKILL_CHEAT: u16 = 0x029;
pub const CMSG_FLAG_QUEST: u16 = 0x02A;
pub const CMSG_FLAG_QUEST_FINISH: u16 = 0x02B;
pub const CMSG_CLEAR_QUEST: u16 = 0x02C;
pub const CMSG_SEND_EVENT: u16 = 0x02D;
pub const CMSG_DEBUG_AISTATE: u16 = 0x02E;
pub const SMSG_DEBUG_AISTATE: u16 = 0x02F;
pub const CMSG_DISABLE_PVP_CHEAT: u16 = 0x030;
pub const CMSG_ADVANCE_SPAWN_TIME: u16 = 0x031;
pub const SMSG_DESTRUCTIBLE_BUILDING_DAMAGE: u16 = 0x032;
pub const CMSG_AUTH_SRP6_BEGIN: u16 = 0x033;
pub const CMSG_AUTH_SRP6_PROOF: u16 = 0x034;
pub const CMSG_AUTH_SRP6_RECODE: u16 = 0x035;
pub const CMSG_CHAR_CREATE: u16 = 0x036;
pub const CMSG_CHAR_ENUM: u16 = 0x037;
pub const CMSG_CHAR_DELETE: u16 = 0x038;
pub const SMSG_AUTH_SRP6_RESPONSE: u16 = 0x039;
pub const SMSG_CHAR_CREATE: u16 = 0x03A;
pub const SMSG_CHAR_ENUM: u16 = 0x03B;
pub const SMSG_CHAR_DELETE: u16 = 0x03C;
pub const CMSG_PLAYER_LOGIN: u16 = 0x03D;
pub const SMSG_NEW_WORLD: u16 = 0x03E;
pub const SMSG_TRANSFER_PENDING: u16 = 0x03F;
pub const SMSG_TRANSFER_ABORTED: u16 = 0x040;
pub const SMSG_CHARACTER_LOGIN_FAILED: u16 = 0x041;
pub const SMSG_LOGIN_SETTIMESPEED: u16 = 0x042;
pub const SMSG_GAMETIME_UPDATE: u16 = 0x043;
pub const CMSG_GAMETIME_SET: u16 = 0x044;
pub const SMSG_GAMETIME_SET: u16 = 0x045;
pub const CMSG_GAMESPEED_SET: u16 = 0x046;
pub const SMSG_GAMESPEED_SET: u16 = 0x047;
pub const CMSG_SERVERTIME: u16 = 0x048;
pub const SMSG_SERVERTIME: u16 = 0x049;
pub const CMSG_PLAYER_LOGOUT: u16 = 0x04A;
pub const CMSG_LOGOUT_REQUEST: u16 = 0x04B;
pub const SMSG_LOGOUT_RESPONSE: u16 = 0x04C;
pub const SMSG_LOGOUT_COMPLETE: u16 = 0x04D;
pub const CMSG_LOGOUT_CANCEL: u16 = 0x04E;
pub const SMSG_LOGOUT_CANCEL_ACK: u16 = 0x04F;
pub const CMSG_NAME_QUERY: u16 = 0x050;
pub const SMSG_NAME_QUERY_RESPONSE: u16 = 0x051;
pub const CMSG_PET_NAME_QUERY: u16 = 0x052;
pub const SMSG_PET_NAME_QUERY_RESPONSE: u16 = 0x053;
pub const CMSG_GUILD_QUERY: u16 = 0x054;
pub const SMSG_GUILD_QUERY_RESPONSE: u16 = 0x055;
pub const CMSG_ITEM_QUERY_SINGLE: u16 = 0x056;
pub const CMSG_ITEM_QUERY_MULTIPLE: u16 = 0x057;
pub const SMSG_ITEM_QUERY_SINGLE_RESPONSE: u16 = 0x058;
pub const SMSG_ITEM_QUERY_MULTIPLE_RESPONSE: u16 = 0x059;
pub const CMSG_PAGE_TEXT_QUERY: u16 = 0x05A;
pub const SMSG_PAGE_TEXT_QUERY_RESPONSE: u16 = 0x05B;
pub const CMSG_QUEST_QUERY: u16 = 0x05C;
pub const SMSG_QUEST_QUERY_RESPONSE: u16 = 0x05D;
pub const CMSG_GAMEOBJECT_QUERY: u16 = 0x05E;
pub const SMSG_GAMEOBJECT_QUERY_RESPONSE: u16 = 0x05F;
pub const CMSG_CREATURE_QUERY: u16 = 0x060;
pub const SMSG_CREATURE_QUERY_RESPONSE: u16 = 0x061;
pub const CMSG_WHO: u16 = 0x062;
pub const SMSG_WHO: u16 = 0x063;
pub const CMSG_WHOIS: u16 = 0x064;
pub const SMSG_WHOIS: u16 = 0x065;
pub const CMSG_CONTACT_LIST: u16 = 0x066;
pub const SMSG_CONTACT_LIST: u16 = 0x067;
pub const SMSG_FRIEND_STATUS: u16 = 0x068;
pub const CMSG_ADD_FRIEND: u16 = 0x069;
pub const CMSG_DEL_FRIEND: u16 = 0x06A;
pub const CMSG_SET_CONTACT_NOTES: u16 = 0x06B;
pub const CMSG_ADD_IGNORE: u16 = 0x06C;
pub const CMSG_DEL_IGNORE: u16 = 0x06D;
pub const CMSG_GROUP_INVITE: u16 = 0x06E;
pub const SMSG_GROUP_INVITE: u16 = 0x06F;
pub const CMSG_GROUP_CANCEL: u16 = 0x070;
pub const SMSG_GROUP_CANCEL: u16 = 0x071;
pub const CMSG_GROUP_ACCEPT: u16 = 0x072;
pub const CMSG_GROUP_DECLINE: u16 = 0x073;
pub const SMSG_GROUP_DECLINE: u16 = 0x074;
pub const CMSG_GROUP_UNINVITE: u16 = 0x075;
pub const CMSG_GROUP_UNINVITE_GUID: u16 = 0x076;
pub const SMSG_GROUP_UNINVITE: u16 = 0x077;
pub const CMSG_GROUP_SET_LEADER: u16 = 0x078;
pub const SMSG_GROUP_SET_LEADER: u16 = 0x079;
pub const CMSG_LOOT_METHOD: u16 = 0x07A;
pub const CMSG_GROUP_DISBAND: u16 = 0x07B;
pub const SMSG_GROUP_DESTROYED: u16 = 0x07C;
pub const SMSG_GROUP_LIST: u16 = 0x07D;
pub const SMSG_PARTY_MEMBER_STATS: u16 = 0x07E;
pub const SMSG_PARTY_COMMAND_RESULT: u16 = 0x07F;
pub const UMSG_UPDATE_GROUP_MEMBERS: u16 = 0x080;
pub const CMSG_GUILD_CREATE: u16 = 0x081;
pub const CMSG_GUILD_INVITE: u16 = 0x082;
pub const SMSG_GUILD_INVITE: u16 = 0x083;
pub const CMSG_GUILD_ACCEPT: u16 = 0x084;
pub const CMSG_GUILD_DECLINE: u16 = 0x085;
pub const SMSG_GUILD_DECLINE: u16 = 0x086;
pub const CMSG_GUILD_INFO: u16 = 0x087;
pub const SMSG_GUILD_INFO: u16 = 0x088;
pub const CMSG_GUILD_ROSTER: u16 = 0x089;
pub const SMSG_GUILD_ROSTER: u16 = 0x08A;
pub const CMSG_GUILD_PROMOTE: u16 = 0x08B;
pub const CMSG_GUILD_DEMOTE: u16 = 0x08C;
pub const CMSG_GUILD_LEAVE: u16 = 0x08D;
pub const CMSG_GUILD_REMOVE: u16 = 0x08E;
pub const CMSG_GUILD_DISBAND: u16 = 0x08F;
pub const CMSG_GUILD_LEADER: u16 = 0x090;
pub const CMSG_GUILD_MOTD: u16 = 0x091;
pub const SMSG_GUILD_EVENT: u16 = 0x092;
pub const SMSG_GUILD_COMMAND_RESULT: u16 = 0x093;
pub const UMSG_UPDATE_GUILD: u16 = 0x094;
pub const CMSG_MESSAGECHAT: u16 = 0x095;
pub const SMSG_MESSAGECHAT: u16 = 0x096;
pub const CMSG_JOIN_CHANNEL: u16 = 0x097;
pub const CMSG_LEAVE_CHANNEL: u16 = 0x098;
pub const SMSG_CHANNEL_NOTIFY: u16 = 0x099;
pub const CMSG_CHANNEL_LIST: u16 = 0x09A;
pub const SMSG_CHANNEL_LIST: u16 = 0x09B;
pub const CMSG_CHANNEL_PASSWORD: u16 = 0x09C;
pub const CMSG_CHANNEL_SET_OWNER: u16 = 0x09D;
pub const CMSG_CHANNEL_OWNER: u16 = 0x09E;
pub const CMSG_CHANNEL_MODERATOR: u16 = 0x09F;
pub const CMSG_CHANNEL_UNMODERATOR: u16 = 0x0A0;
pub const CMSG_CHANNEL_MUTE: u16 = 0x0A1;
pub const CMSG_CHANNEL_UNMUTE: u16 = 0x0A2;
pub const CMSG_CHANNEL_INVITE: u16 = 0x0A3;
pub const CMSG_CHANNEL_KICK: u16 = 0x0A4;
pub const CMSG_CHANNEL_BAN: u16 = 0x0A5;
pub const CMSG_CHANNEL_UNBAN: u16 = 0x0A6;
pub const CMSG_CHANNEL_ANNOUNCEMENTS: u16 = 0x0A7;
pub const CMSG_CHANNEL_MODERATE: u16 = 0x0A8;
pub const SMSG_UPDATE_OBJECT: u16 = 0x0A9;
pub const SMSG_DESTROY_OBJECT: u16 = 0x0AA;
pub const CMSG_USE_ITEM: u16 = 0x0AB;
pub const CMSG_OPEN_ITEM: u16 = 0x0AC;
pub const CMSG_READ_ITEM: u16 = 0x0AD;
pub const SMSG_READ_ITEM_OK: u16 = 0x0AE;
pub const SMSG_READ_ITEM_FAILED: u16 = 0x0AF;
pub const SMSG_ITEM_COOLDOWN: u16 = 0x0B0;
pub const CMSG_GAMEOBJ_USE: u16 = 0x0B1;
pub const CMSG_DESTROY_ITEMS: u16 = 0x0B2;
pub const SMSG_GAMEOBJECT_CUSTOM_ANIM: u16 = 0x0B3;
pub const CMSG_AREATRIGGER: u16 = 0x0B4;
pub const MSG_MOVE_START_FORWARD: u16 = 0x0B5;
pub const MSG_MOVE_START_BACKWARD: u16 = 0x0B6;
pub const MSG_MOVE_STOP: u16 = 0x0B7;
pub const MSG_MOVE_START_STRAFE_LEFT: u16 = 0x0B8;
pub const MSG_MOVE_START_STRAFE_RIGHT: u16 = 0x0B9;
pub const MSG_MOVE_STOP_STRAFE: u16 = 0x0BA;
pub const MSG_MOVE_JUMP: u16 = 0x0BB;
pub const MSG_MOVE_START_TURN_LEFT: u16 = 0x0BC;
pub const MSG_MOVE_START_TURN_RIGHT: u16 = 0x0BD;
pub const MSG_MOVE_STOP_TURN: u16 = 0x0BE;
pub const MSG_MOVE_START_PITCH_UP: u16 = 0x0BF;
pub const MSG_MOVE_START_PITCH_DOWN: u16 = 0x0C0;
pub const MSG_MOVE_STOP_PITCH: u16 = 0x0C1;
pub const MSG_MOVE_SET_RUN_MODE: u16 = 0x0C2;
pub const MSG_MOVE_SET_WALK_MODE: u16 = 0x0C3;
pub const MSG_MOVE_TOGGLE_LOGGING: u16 = 0x0C4;
pub const MSG_MOVE_TELEPORT: u16 = 0x0C5;
pub const MSG_MOVE_TELEPORT_CHEAT: u16 = 0x0C6;
pub const MSG_MOVE_TELEPORT_ACK: u16 = 0x0C7;
pub const MSG_MOVE_TOGGLE_FALL_LOGGING: u16 = 0x0C8;
pub const MSG_MOVE_FALL_LAND: u16 = 0x0C9;
pub const MSG_MOVE_START_SWIM: u16 = 0x0CA;
pub const MSG_MOVE_STOP_SWIM: u16 = 0x0CB;
pub const MSG_MOVE_SET_RUN_SPEED_CHEAT: u16 = 0x0CC;
pub const MSG_MOVE_SET_RUN_SPEED: u16 = 0x0CD;
pub const MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT: u16 = 0x0CE;
pub const MSG_MOVE_SET_RUN_BACK_SPEED: u16 = 0x0CF;
pub const MSG_MOVE_SET_WALK_SPEED_CHEAT: u16 = 0x0D0;
pub const MSG_MOVE_SET_WALK_SPEED: u16 = 0x0D1;
pub const MSG_MOVE_SET_SWIM_SPEED_CHEAT: u16 = 0x0D2;
pub const MSG_MOVE_SET_SWIM_SPEED: u16 = 0x0D3;
pub const MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT: u16 = 0x0D4;
pub const MSG_MOVE_SET_SWIM_BACK_SPEED: u16 = 0x0D5;
pub const MSG_MOVE_SET_ALL_SPEED_CHEAT: u16 = 0x0D6;
pub const MSG_MOVE_SET_TURN_RATE_CHEAT: u16 = 0x0D7;
pub const MSG_MOVE_SET_TURN_RATE: u16 = 0x0D8;
pub const MSG_MOVE_TOGGLE_COLLISION_CHEAT: u16 = 0x0D9;
pub const MSG_MOVE_SET_FACING: u16 = 0x0DA;
pub const MSG_MOVE_SET_PITCH: u16 = 0x0DB;
pub const MSG_MOVE_WORLDPORT_ACK: u16 = 0x0DC;
pub const SMSG_MONSTER_MOVE: u16 = 0x0DD;
pub const SMSG_MOVE_WATER_WALK: u16 = 0x0DE;
pub const SMSG_MOVE_LAND_WALK: u16 = 0x0DF;
pub const CMSG_MOVE_CHARM_PORT_CHEAT: u16 = 0x0E0;
pub const CMSG_MOVE_SET_RAW_POSITION: u16 = 0x0E1;
pub const SMSG_FORCE_RUN_SPEED_CHANGE: u16 = 0x0E2;
pub const CMSG_FORCE_RUN_SPEED_CHANGE_ACK: u16 = 0x0E3;
pub const SMSG_FORCE_RUN_BACK_SPEED_CHANGE: u16 = 0x0E4;
pub const CMSG_FORCE_RUN_BACK_SPEED_CHANGE_ACK: u16 = 0x0E5;
pub const SMSG_FORCE_SWIM_SPEED_CHANGE: u16 = 0x0E6;
pub const CMSG_FORCE_SWIM_SPEED_CHANGE_ACK: u16 = 0x0E7;
pub const SMSG_FORCE_MOVE_ROOT: u16 = 0x0E8;
pub const CMSG_FORCE_MOVE_ROOT_ACK: u16 = 0x0E9;
pub const SMSG_FORCE_MOVE_UNROOT: u16 = 0x0EA;
pub const CMSG_FORCE_MOVE_UNROOT_ACK: u16 = 0x0EB;
pub const MSG_MOVE_ROOT: u16 = 0x0EC;
pub const MSG_MOVE_UNROOT: u16 = 0x0ED;
pub const MSG_MOVE_HEARTBEAT: u16 = 0x0EE;
pub const SMSG_MOVE_KNOCK_BACK: u16 = 0x0EF;
pub const CMSG_MOVE_KNOCK_BACK_ACK: u16 = 0x0F0;
pub const MSG_MOVE_KNOCK_BACK: u16 = 0x0F1;
pub const SMSG_MOVE_FEATHER_FALL: u16 = 0x0F2;
pub const SMSG_MOVE_NORMAL_FALL: u16 = 0x0F3;
pub const SMSG_MOVE_SET_HOVER: u16 = 0x0F4;
pub const SMSG_MOVE_UNSET_HOVER: u16 = 0x0F5;
pub const CMSG_MOVE_HOVER_ACK: u16 = 0x0F6;
pub const MSG_MOVE_HOVER: u16 = 0x0F7;
pub const CMSG_TRIGGER_CINEMATIC_CHEAT: u16 = 0x0F8;
pub const CMSG_OPENING_CINEMATIC: u16 = 0x0F9;
pub const SMSG_TRIGGER_CINEMATIC: u16 = 0x0FA;
pub const CMSG_NEXT_CINEMATIC_CAMERA: u16 = 0x0FB;
pub const CMSG_COMPLETE_CINEMATIC: u16 = 0x0FC;
pub const SMSG_TUTORIAL_FLAGS: u16 = 0x0FD;
pub const CMSG_TUTORIAL_FLAG: u16 = 0x0FE;
pub const CMSG_TUTORIAL_CLEAR: u16 = 0x0FF;
pub const CMSG_TUTORIAL_RESET: u16 = 0x100;
pub const CMSG_STANDSTATECHANGE: u16 = 0x101;
pub const CMSG_EMOTE: u16 = 0x102;
pub const SMSG_EMOTE: u16 = 0x103;
pub const CMSG_TEXT_EMOTE: u16 = 0x104;
pub const SMSG_TEXT_EMOTE: u16 = 0x105;
pub const CMSG_AUTOEQUIP_GROUND_ITEM: u16 = 0x106;
pub const CMSG_AUTOSTORE_GROUND_ITEM: u16 = 0x107;
pub const CMSG_AUTOSTORE_LOOT_ITEM: u16 = 0x108;
pub const CMSG_STORE_LOOT_IN_SLOT: u16 = 0x109;
pub const CMSG_AUTOEQUIP_ITEM: u16 = 0x10A;
pub const CMSG_AUTOSTORE_BAG_ITEM: u16 = 0x10B;
pub const CMSG_SWAP_ITEM: u16 = 0x10C;
pub const CMSG_SWAP_INV_ITEM: u16 = 0x10D;
pub const CMSG_SPLIT_ITEM: u16 = 0x10E;
pub const CMSG_AUTOEQUIP_ITEM_SLOT: u16 = 0x10F;
pub const CMSG_UNCLAIM_LICENSE: u16 = 0x110;
pub const CMSG_DESTROYITEM: u16 = 0x111;
pub const SMSG_INVENTORY_CHANGE_FAILURE: u16 = 0x112;
pub const SMSG_OPEN_CONTAINER: u16 = 0x113;
pub const CMSG_INSPECT: u16 = 0x114;
pub const SMSG_INSPECT_RESULTS_UPDATE: u16 = 0x115;
pub const CMSG_INITIATE_TRADE: u16 = 0x116;
pub const CMSG_BEGIN_TRADE: u16 = 0x117;
pub const CMSG_BUSY_TRADE: u16 = 0x118;
pub const CMSG_IGNORE_TRADE: u16 = 0x119;
pub const CMSG_ACCEPT_TRADE: u16 = 0x11A;
pub const CMSG_UNACCEPT_TRADE: u16 = 0x11B;
pub const CMSG_CANCEL_TRADE: u16 = 0x11C;
pub const CMSG_SET_TRADE_ITEM: u16 = 0x11D;
pub const CMSG_CLEAR_TRADE_ITEM: u16 = 0x11E;
pub const CMSG_SET_TRADE_GOLD: u16 = 0x11F;
pub const SMSG_TRADE_STATUS: u16 = 0x120;
pub const SMSG_TRADE_STATUS_EXTENDED: u16 = 0x121;
pub const SMSG_INITIALIZE_FACTIONS: u16 = 0x122;
pub const SMSG_SET_FACTION_VISIBLE: u16 = 0x123;
pub const SMSG_SET_FACTION_STANDING: u16 = 0x124;
pub const CMSG_SET_FACTION_ATWAR: u16 = 0x125;
pub const CMSG_SET_FACTION_CHEAT: u16 = 0x126;
pub const SMSG_SET_PROFICIENCY: u16 = 0x127;
pub const CMSG_SET_ACTION_BUTTON: u16 = 0x128;
pub const SMSG_ACTION_BUTTONS: u16 = 0x129;
pub const SMSG_INITIAL_SPELLS: u16 = 0x12A;
pub const SMSG_LEARNED_SPELL: u16 = 0x12B;
pub const SMSG_SUPERCEDED_SPELL: u16 = 0x12C;
pub const CMSG_NEW_SPELL_SLOT: u16 = 0x12D;
pub const CMSG_CAST_SPELL: u16 = 0x12E;
pub const CMSG_CANCEL_CAST: u16 = 0x12F;
pub const SMSG_CAST_FAILED: u16 = 0x130;
pub const SMSG_SPELL_START: u16 = 0x131;
pub const SMSG_SPELL_GO: u16 = 0x132;
pub const SMSG_SPELL_FAILURE: u16 = 0x133;
pub const SMSG_SPELL_COOLDOWN: u16 = 0x134;
pub const SMSG_COOLDOWN_EVENT: u16 = 0x135;
pub const CMSG_CANCEL_AURA: u16 = 0x136;
pub const SMSG_EQUIPMENT_SET_ID: u16 = 0x137;
pub const SMSG_PET_CAST_FAILED: u16 = 0x138;
pub const MSG_CHANNEL_START: u16 = 0x139;
pub const MSG_CHANNEL_UPDATE: u16 = 0x13A;
pub const CMSG_CANCEL_CHANNELLING: u16 = 0x13B;
pub const SMSG_AI_REACTION: u16 = 0x13C;
pub const CMSG_SET_SELECTION: u16 = 0x13D;
pub const CMSG_DELETEEQUIPMENT_SET: u16 = 0x13E;
pub const CMSG_INSTANCE_LOCK_RESPONSE: u16 = 0x13F;
pub const CMSG_DEBUG_PASSIVE_AURA: u16 = 0x140;
pub const CMSG_ATTACKSWING: u16 = 0x141;
pub const CMSG_ATTACKSTOP: u16 = 0x142;
pub const SMSG_ATTACKSTART: u16 = 0x143;
pub const SMSG_ATTACKSTOP: u16 = 0x144;
pub const SMSG_ATTACKSWING_NOTINRANGE: u16 = 0x145;
pub const SMSG_ATTACKSWING_BADFACING: u16 = 0x146;
pub const SMSG_PENDING_RAID_LOCK: u16 = 0x147;
pub const SMSG_ATTACKSWING_DEADTARGET: u16 = 0x148;
pub const SMSG_ATTACKSWING_CANT_ATTACK: u16 = 0x149;
pub const SMSG_ATTACKERSTATEUPDATE: u16 = 0x14A;
pub const SMSG_BATTLEFIELD_PORT_DENIED: u16 = 0x14B;
pub const CMSG_PERFORM_ACTION_SET: u16 = 0x14C;
pub const SMSG_RESUME_CAST_BAR: u16 = 0x14D;
pub const SMSG_CANCEL_COMBAT: u16 = 0x14E;
pub const SMSG_SPELLBREAKLOG: u16 = 0x14F;
pub const SMSG_SPELLHEALLOG: u16 = 0x150;
pub const SMSG_SPELLENERGIZELOG: u16 = 0x151;
pub const SMSG_BREAK_TARGET: u16 = 0x152;
pub const CMSG_SAVE_PLAYER: u16 = 0x153;
pub const CMSG_SETDEATHBINDPOINT: u16 = 0x154;
pub const SMSG_BINDPOINTUPDATE: u16 = 0x155;
pub const CMSG_GETDEATHBINDZONE: u16 = 0x156;
pub const SMSG_BINDZONEREPLY: u16 = 0x157;
pub const SMSG_PLAYERBOUND: u16 = 0x158;
pub const SMSG_CLIENT_CONTROL_UPDATE: u16 = 0x159;
pub const CMSG_REPOP_REQUEST: u16 = 0x15A;
pub const SMSG_RESURRECT_REQUEST: u16 = 0x15B;
pub const CMSG_RESURRECT_RESPONSE: u16 = 0x15C;
pub const CMSG_LOOT: u16 = 0x15D;
pub const CMSG_LOOT_MONEY: u16 = 0x15E;
pub const CMSG_LOOT_RELEASE: u16 = 0x15F;
pub const SMSG_LOOT_RESPONSE: u16 = 0x160;
pub const SMSG_LOOT_RELEASE_RESPONSE: u16 = 0x161;
pub const SMSG_LOOT_REMOVED: u16 = 0x162;
pub const SMSG_LOOT_MONEY_NOTIFY: u16 = 0x163;
pub const SMSG_LOOT_ITEM_NOTIFY: u16 = 0x164;
pub const SMSG_LOOT_CLEAR_MONEY: u16 = 0x165;
pub const SMSG_ITEM_PUSH_RESULT: u16 = 0x166;
pub const SMSG_DUEL_REQUESTED: u16 = 0x167;
pub const SMSG_DUEL_OUTOFBOUNDS: u16 = 0x168;
pub const SMSG_DUEL_INBOUNDS: u16 = 0x169;
pub const SMSG_DUEL_COMPLETE: u16 = 0x16A;
pub const SMSG_DUEL_WINNER: u16 = 0x16B;
pub const CMSG_DUEL_ACCEPTED: u16 = 0x16C;
pub const CMSG_DUEL_CANCELLED: u16 = 0x16D;
pub const SMSG_MOUNTRESULT: u16 = 0x16E;
pub const SMSG_DISMOUNTRESULT: u16 = 0x16F;
pub const SMSG_REMOVED_FROM_PVP_QUEUE: u16 = 0x170;
pub const CMSG_MOUNTSPECIAL_ANIM: u16 = 0x171;
pub const SMSG_MOUNTSPECIAL_ANIM: u16 = 0x172;
pub const SMSG_PET_TAME_FAILURE: u16 = 0x173;
pub const CMSG_PET_SET_ACTION: u16 = 0x174;
pub const CMSG_PET_ACTION: u16 = 0x175;
pub const CMSG_PET_ABANDON: u16 = 0x176;
pub const CMSG_PET_RENAME: u16 = 0x177;
pub const SMSG_PET_NAME_INVALID: u16 = 0x178;
pub const SMSG_PET_SPELLS: u16 = 0x179;
pub const SMSG_PET_MODE: u16 = 0x17A;
pub const CMSG_GOSSIP_HELLO: u16 = 0x17B;
pub const CMSG_GOSSIP_SELECT_OPTION: u16 = 0x17C;
pub const SMSG_GOSSIP_MESSAGE: u16 = 0x17D;
pub const SMSG_GOSSIP_COMPLETE: u16 = 0x17E;
pub const CMSG_NPC_TEXT_QUERY: u16 = 0x17F;
pub const SMSG_NPC_TEXT_UPDATE: u16 = 0x180;
pub const SMSG_NPC_WONT_TALK: u16 = 0x181;
pub const CMSG_QUESTGIVER_STATUS_QUERY: u16 = 0x182;
pub const SMSG_QUESTGIVER_STATUS: u16 = 0x183;
pub const CMSG_QUESTGIVER_HELLO: u16 = 0x184;
pub const SMSG_QUESTGIVER_QUEST_LIST: u16 = 0x185;
pub const CMSG_QUESTGIVER_QUERY_QUEST: u16 = 0x186;
pub const CMSG_QUESTGIVER_QUEST_AUTOLAUNCH: u16 = 0x187;
pub const SMSG_QUESTGIVER_QUEST_DETAILS: u16 = 0x188;
pub const CMSG_QUESTGIVER_ACCEPT_QUEST: u16 = 0x189;
pub const CMSG_QUESTGIVER_COMPLETE_QUEST: u16 = 0x18A;
pub const SMSG_QUESTGIVER_REQUEST_ITEMS: u16 = 0x18B;
pub const CMSG_QUESTGIVER_REQUEST_REWARD: u16 = 0x18C;
pub const SMSG_QUESTGIVER_OFFER_REWARD: u16 = 0x18D;
pub const CMSG_QUESTGIVER_CHOOSE_REWARD: u16 = 0x18E;
pub const SMSG_QUESTGIVER_QUEST_INVALID: u16 = 0x18F;
pub const CMSG_QUESTGIVER_CANCEL: u16 = 0x190;
pub const SMSG_QUESTGIVER_QUEST_COMPLETE: u16 = 0x191;
pub const SMSG_QUESTGIVER_QUEST_FAILED: u16 = 0x192;
pub const CMSG_QUESTLOG_SWAP_QUEST: u16 = 0x193;
pub const CMSG_QUESTLOG_REMOVE_QUEST: u16 = 0x194;
pub const SMSG_QUESTLOG_FULL: u16 = 0x195;
pub const SMSG_QUESTUPDATE_FAILED: u16 = 0x196;
pub const SMSG_QUESTUPDATE_FAILEDTIMER: u16 = 0x197;
pub const SMSG_QUESTUPDATE_COMPLETE: u16 = 0x198;
pub const SMSG_QUESTUPDATE_ADD_KILL: u16 = 0x199;
pub const SMSG_QUESTUPDATE_ADD_ITEM_OBSOLETE: u16 = 0x19A;
pub const CMSG_QUEST_CONFIRM_ACCEPT: u16 = 0x19B;
pub const SMSG_QUEST_CONFIRM_ACCEPT: u16 = 0x19C;
pub const CMSG_PUSHQUESTTOPARTY: u16 = 0x19D;
pub const CMSG_LIST_INVENTORY: u16 = 0x19E;
pub const SMSG_LIST_INVENTORY: u16 = 0x19F;
pub const CMSG_SELL_ITEM: u16 = 0x1A0;
pub const SMSG_SELL_ITEM: u16 = 0x1A1;
pub const CMSG_BUY_ITEM: u16 = 0x1A2;
pub const CMSG_BUY_ITEM_IN_SLOT: u16 = 0x1A3;
pub const SMSG_BUY_ITEM: u16 = 0x1A4;
pub const SMSG_BUY_FAILED: u16 = 0x1A5;
pub const CMSG_TAXICLEARALLNODES: u16 = 0x1A6;
pub const CMSG_TAXIENABLEALLNODES: u16 = 0x1A7;
pub const CMSG_TAXISHOWNODES: u16 = 0x1A8;
pub const SMSG_SHOWTAXINODES: u16 = 0x1A9;
pub const CMSG_TAXINODE_STATUS_QUERY: u16 = 0x1AA;
pub const SMSG_TAXINODE_STATUS: u16 = 0x1AB;
pub const CMSG_TAXIQUERYAVAILABLENODES: u16 = 0x1AC;
pub const CMSG_ACTIVATETAXI: u16 = 0x1AD;
pub const SMSG_ACTIVATETAXIREPLY: u16 = 0x1AE;
pub const SMSG_NEW_TAXI_PATH: u16 = 0x1AF;
pub const CMSG_TRAINER_LIST: u16 = 0x1B0;
pub const SMSG_TRAINER_LIST: u16 = 0x1B1;
pub const CMSG_TRAINER_BUY_SPELL: u16 = 0x1B2;
pub const SMSG_TRAINER_BUY_SUCCEEDED: u16 = 0x1B3;
pub const SMSG_TRAINER_BUY_FAILED: u16 = 0x1B4;
pub const CMSG_BINDER_ACTIVATE: u16 = 0x1B5;
pub const SMSG_PLAYERBINDERROR: u16 = 0x1B6;
pub const CMSG_BANKER_ACTIVATE: u16 = 0x1B7;
pub const SMSG_SHOW_BANK: u16 = 0x1B8;
pub const CMSG_BUY_BANK_SLOT: u16 = 0x1B9;
pub const SMSG_BUY_BANK_SLOT_RESULT: u16 = 0x1BA;
pub const CMSG_PETITION_SHOWLIST: u16 = 0x1BB;
pub const SMSG_PETITION_SHOWLIST: u16 = 0x1BC;
pub const CMSG_PETITION_BUY: u16 = 0x1BD;
pub const CMSG_PETITION_SHOW_SIGNATURES: u16 = 0x1BE;
pub const SMSG_PETITION_SHOW_SIGNATURES: u16 = 0x1BF;
pub const CMSG_PETITION_SIGN: u16 = 0x1C0;
pub const SMSG_PETITION_SIGN_RESULTS: u16 = 0x1C1;
pub const MSG_PETITION_DECLINE: u16 = 0x1C2;
pub const CMSG_OFFER_PETITION: u16 = 0x1C3;
pub const CMSG_TURN_IN_PETITION: u16 = 0x1C4;
pub const SMSG_TURN_IN_PETITION_RESULTS: u16 = 0x1C5;
pub const CMSG_PETITION_QUERY: u16 = 0x1C6;
pub const SMSG_PETITION_QUERY_RESPONSE: u16 = 0x1C7;
pub const SMSG_FISH_NOT_HOOKED: u16 = 0x1C8;
pub const SMSG_FISH_ESCAPED: u16 = 0x1C9;
pub const CMSG_BUG: u16 = 0x1CA;
pub const SMSG_NOTIFICATION: u16 = 0x1CB;
pub const CMSG_PLAYED_TIME: u16 = 0x1CC;
pub const SMSG_PLAYED_TIME: u16 = 0x1CD;
pub const CMSG_QUERY_TIME: u16 = 0x1CE;
pub const SMSG_QUERY_TIME_RESPONSE: u16 = 0x1CF;
pub const SMSG_LOG_XPGAIN: u16 = 0x1D0;
pub const SMSG_AURACASTLOG: u16 = 0x1D1;
pub const CMSG_RECLAIM_CORPSE: u16 = 0x1D2;
pub const CMSG_WRAP_ITEM: u16 = 0x1D3;
pub const SMSG_LEVELUP_INFO: u16 = 0x1D4;
pub const MSG_MINIMAP_PING: u16 = 0x1D5;
pub const SMSG_RESISTLOG: u16 = 0x1D6;
pub const SMSG_ENCHANTMENTLOG: u16 = 0x1D7;
pub const CMSG_SET_SKILL_CHEAT: u16 = 0x1D8;
pub const SMSG_START_MIRROR_TIMER: u16 = 0x1D9;
pub const SMSG_PAUSE_MIRROR_TIMER: u16 = 0x1DA;
pub const SMSG_STOP_MIRROR_TIMER: u16 = 0x1DB;
pub const CMSG_PING: u16 = 0x1DC;
pub const SMSG_PONG: u16 = 0x1DD;
pub const SMSG_CLEAR_COOLDOWN: u16 = 0x1DE;
pub const SMSG_GAMEOBJECT_PAGETEXT: u16 = 0x1DF;
pub const CMSG_SETSHEATHED: u16 = 0x1E0;
pub const SMSG_COOLDOWN_CHEAT: u16 = 0x1E1;
pub const SMSG_SPELL_DELAYED: u16 = 0x1E2;
pub const CMSG_QUEST_POI_QUERY: u16 = 0x1E3;
pub const SMSG_QUEST_POI_QUERY_RESPONSE: u16 = 0x1E4;
pub const CMSG_GHOST: u16 = 0x1E5;
pub const CMSG_GM_INVIS: u16 = 0x1E6;
pub const SMSG_INVALID_PROMOTION_CODE: u16 = 0x1E7;
pub const MSG_GM_BIND_OTHER: u16 = 0x1E8;
pub const MSG_GM_SUMMON: u16 = 0x1E9;
pub const SMSG_ITEM_TIME_UPDATE: u16 = 0x1EA;
pub const SMSG_ITEM_ENCHANT_TIME_UPDATE: u16 = 0x1EB;
pub const SMSG_AUTH_CHALLENGE: u16 = 0x1EC;
pub const CMSG_AUTH_SESSION: u16 = 0x1ED;
pub const SMSG_AUTH_RESPONSE: u16 = 0x1EE;
pub const MSG_GM_SHOWLABEL: u16 = 0x1EF;
pub const CMSG_PET_CAST_SPELL: u16 = 0x1F0;
pub const MSG_SAVE_GUILD_EMBLEM: u16 = 0x1F1;
pub const MSG_TABARDVENDOR_ACTIVATE: u16 = 0x1F2;
pub const SMSG_PLAY_SPELL_VISUAL: u16 = 0x1F3;
pub const CMSG_ZONEUPDATE: u16 = 0x1F4;
pub const SMSG_PARTYKILLLOG: u16 = 0x1F5;
pub const SMSG_COMPRESSED_UPDATE_OBJECT: u16 = 0x1F6;
pub const SMSG_PLAY_SPELL_IMPACT: u16 = 0x1F7;
pub const SMSG_EXPLORATION_EXPERIENCE: u16 = 0x1F8;
pub const CMSG_GM_SET_SECURITY_GROUP: u16 = 0x1F9;
pub const CMSG_GM_NUKE: u16 = 0x1FA;
pub const MSG_RANDOM_ROLL: u16 = 0x1FB;
pub const SMSG_ENVIRONMENTALDAMAGELOG: u16 = 0x1FC;
pub const CMSG_CHANGEPLAYER_DIFFICULTY: u16 = 0x1FD;
pub const SMSG_RWHOIS: u16 = 0x1FE;
pub const SMSG_LFG_PLAYER_REWARD: u16 = 0x1FF;
pub const SMSG_LFG_TELEPORT_DENIED: u16 = 0x200;
pub const CMSG_UNLEARN_SPELL: u16 = 0x201;
pub const CMSG_UNLEARN_SKILL: u16 = 0x202;
pub const SMSG_REMOVED_SPELL: u16 = 0x203;
pub const CMSG_DECHARGE: u16 = 0x204;
pub const CMSG_GMTICKET_CREATE: u16 = 0x205;
pub const SMSG_GMTICKET_CREATE: u16 = 0x206;
pub const CMSG_GMTICKET_UPDATETEXT: u16 = 0x207;
pub const SMSG_GMTICKET_UPDATETEXT: u16 = 0x208;
pub const SMSG_ACCOUNT_DATA_TIMES: u16 = 0x209;
pub const CMSG_REQUEST_ACCOUNT_DATA: u16 = 0x20A;
pub const CMSG_UPDATE_ACCOUNT_DATA: u16 = 0x20B;
pub const SMSG_UPDATE_ACCOUNT_DATA: u16 = 0x20C;
pub const SMSG_CLEAR_FAR_SIGHT_IMMEDIATE: u16 = 0x20D;
pub const SMSG_CHANGEPLAYER_DIFFICULTY_RESULT: u16 = 0x20E;
pub const CMSG_GM_TEACH: u16 = 0x20F;
pub const CMSG_GM_CREATE_ITEM_TARGET: u16 = 0x210;
pub const CMSG_GMTICKET_GETTICKET: u16 = 0x211;
pub const SMSG_GMTICKET_GETTICKET: u16 = 0x212;
pub const CMSG_UNLEARN_TALENTS: u16 = 0x213;
pub const SMSG_INSTANCE_ENCOUNTER: u16 = 0x214;
pub const SMSG_GAMEOBJECT_DESPAWN_ANIM: u16 = 0x215;
pub const MSG_CORPSE_QUERY: u16 = 0x216;
pub const CMSG_GMTICKET_DELETETICKET: u16 = 0x217;
pub const SMSG_GMTICKET_DELETETICKET: u16 = 0x218;
pub const SMSG_CHAT_WRONG_FACTION: u16 = 0x219;
pub const CMSG_GMTICKET_SYSTEMSTATUS: u16 = 0x21A;
pub const SMSG_GMTICKET_SYSTEMSTATUS: u16 = 0x21B;
pub const CMSG_SPIRIT_HEALER_ACTIVATE: u16 = 0x21C;
pub const CMSG_SET_STAT_CHEAT: u16 = 0x21D;
pub const SMSG_QUEST_FORCE_REMOVED: u16 = 0x21E;
pub const CMSG_SKILL_BUY_STEP: u16 = 0x21F;
pub const CMSG_SKILL_BUY_RANK: u16 = 0x220;
pub const CMSG_XP_CHEAT: u16 = 0x221;
pub const SMSG_SPIRIT_HEALER_CONFIRM: u16 = 0x222;
pub const CMSG_CHARACTER_POINT_CHEAT: u16 = 0x223;
pub const SMSG_GOSSIP_POI: u16 = 0x224;
pub const CMSG_CHAT_IGNORED: u16 = 0x225;
pub const CMSG_GM_VISION: u16 = 0x226;
pub const CMSG_SERVER_COMMAND: u16 = 0x227;
pub const CMSG_GM_SILENCE: u16 = 0x228;
pub const CMSG_GM_REVEALTO: u16 = 0x229;
pub const CMSG_GM_RESURRECT: u16 = 0x22A;
pub const CMSG_GM_SUMMONMOB: u16 = 0x22B;
pub const CMSG_GM_MOVECORPSE: u16 = 0x22C;
pub const CMSG_GM_FREEZE: u16 = 0x22D;
pub const CMSG_GM_UBERINVIS: u16 = 0x22E;
pub const CMSG_GM_REQUEST_PLAYER_INFO: u16 = 0x22F;
pub const SMSG_GM_PLAYER_INFO: u16 = 0x230;
pub const CMSG_GUILD_RANK: u16 = 0x231;
pub const CMSG_GUILD_ADD_RANK: u16 = 0x232;
pub const CMSG_GUILD_DEL_RANK: u16 = 0x233;
pub const CMSG_GUILD_SET_PUBLIC_NOTE: u16 = 0x234;
pub const CMSG_GUILD_SET_OFFICER_NOTE: u16 = 0x235;
pub const SMSG_LOGIN_VERIFY_WORLD: u16 = 0x236;
pub const CMSG_CLEAR_EXPLORATION: u16 = 0x237;
pub const CMSG_SEND_MAIL: u16 = 0x238;
pub const SMSG_SEND_MAIL_RESULT: u16 = 0x239;
pub const CMSG_GET_MAIL_LIST: u16 = 0x23A;
pub const SMSG_MAIL_LIST_RESULT: u16 = 0x23B;
pub const CMSG_BATTLEFIELD_LIST: u16 = 0x23C;
pub const SMSG_BATTLEFIELD_LIST: u16 = 0x23D;
pub const CMSG_BATTLEFIELD_JOIN: u16 = 0x23E;
pub const SMSG_FORCE_SET_VEHICLE_REC_ID: u16 = 0x23F;
pub const CMSG_SET_VEHICLE_REC_ID_ACK: u16 = 0x240;
pub const CMSG_TAXICLEARNODE: u16 = 0x241;
pub const CMSG_TAXIENABLENODE: u16 = 0x242;
pub const CMSG_ITEM_TEXT_QUERY: u16 = 0x243;
pub const SMSG_ITEM_TEXT_QUERY_RESPONSE: u16 = 0x244;
pub const CMSG_MAIL_TAKE_MONEY: u16 = 0x245;
pub const CMSG_MAIL_TAKE_ITEM: u16 = 0x246;
pub const CMSG_MAIL_MARK_AS_READ: u16 = 0x247;
pub const CMSG_MAIL_RETURN_TO_SENDER: u16 = 0x248;
pub const CMSG_MAIL_DELETE: u16 = 0x249;
pub const CMSG_MAIL_CREATE_TEXT_ITEM: u16 = 0x24A;
pub const SMSG_SPELLLOGMISS: u16 = 0x24B;
pub const SMSG_SPELLLOGEXECUTE: u16 = 0x24C;
pub const SMSG_DEBUGAURAPROC: u16 = 0x24D;
pub const SMSG_PERIODICAURALOG: u16 = 0x24E;
pub const SMSG_SPELLDAMAGESHIELD: u16 = 0x24F;
pub const SMSG_SPELLNONMELEEDAMAGELOG: u16 = 0x250;
pub const CMSG_LEARN_TALENT: u16 = 0x251;
pub const SMSG_RESURRECT_FAILED: u16 = 0x252;
pub const CMSG_TOGGLE_PVP: u16 = 0x253;
pub const SMSG_ZONE_UNDER_ATTACK: u16 = 0x254;
pub const MSG_AUCTION_HELLO: u16 = 0x255;
pub const CMSG_AUCTION_SELL_ITEM: u16 = 0x256;
pub const CMSG_AUCTION_REMOVE_ITEM: u16 = 0x257;
pub const CMSG_AUCTION_LIST_ITEMS: u16 = 0x258;
pub const CMSG_AUCTION_LIST_OWNER_ITEMS: u16 = 0x259;
pub const CMSG_AUCTION_PLACE_BID: u16 = 0x25A;
pub const SMSG_AUCTION_COMMAND_RESULT: u16 = 0x25B;
pub const SMSG_AUCTION_LIST_RESULT: u16 = 0x25C;
pub const SMSG_AUCTION_OWNER_LIST_RESULT: u16 = 0x25D;
pub const SMSG_AUCTION_BIDDER_NOTIFICATION: u16 = 0x25E;
pub const SMSG_AUCTION_OWNER_NOTIFICATION: u16 = 0x25F;
pub const SMSG_PROCRESIST: u16 = 0x260;
pub const SMSG_COMBAT_EVENT_FAILED: u16 = 0x261;
pub const SMSG_DISPEL_FAILED: u16 = 0x262;
pub const SMSG_SPELLORDAMAGE_IMMUNE: u16 = 0x263;
pub const CMSG_AUCTION_LIST_BIDDER_ITEMS: u16 = 0x264;
pub const SMSG_AUCTION_BIDDER_LIST_RESULT: u16 = 0x265;
pub const SMSG_SET_FLAT_SPELL_MODIFIER: u16 = 0x266;
pub const SMSG_SET_PCT_SPELL_MODIFIER: u16 = 0x267;
pub const CMSG_SET_AMMO: u16 = 0x268;
pub const SMSG_CORPSE_RECLAIM_DELAY: u16 = 0x269;
pub const CMSG_SET_ACTIVE_MOVER: u16 = 0x26A;
pub const CMSG_PET_CANCEL_AURA: u16 = 0x26B;
pub const CMSG_PLAYER_AI_CHEAT: u16 = 0x26C;
pub const CMSG_CANCEL_AUTO_REPEAT_SPELL: u16 = 0x26D;
pub const MSG_GM_ACCOUNT_ONLINE: u16 = 0x26E;
pub const MSG_LIST_STABLED_PETS: u16 = 0x26F;
pub const CMSG_STABLE_PET: u16 = 0x270;
pub const CMSG_UNSTABLE_PET: u16 = 0x271;
pub const CMSG_BUY_STABLE_SLOT: u16 = 0x272;
pub const SMSG_STABLE_RESULT: u16 = 0x273;
pub const CMSG_STABLE_REVIVE_PET: u16 = 0x274;
pub const CMSG_STABLE_SWAP_PET: u16 = 0x275;
pub const MSG_QUEST_PUSH_RESULT: u16 = 0x276;
pub const SMSG_PLAY_MUSIC: u16 = 0x277;
pub const SMSG_PLAY_OBJECT_SOUND: u16 = 0x278;
pub const CMSG_REQUEST_PET_INFO: u16 = 0x279;
pub const CMSG_FAR_SIGHT: u16 = 0x27A;
pub const SMSG_SPELLDISPELLOG: u16 = 0x27B;
pub const SMSG_DAMAGE_CALC_LOG: u16 = 0x27C;
pub const CMSG_ENABLE_DAMAGE_LOG: u16 = 0x27D;
pub const CMSG_GROUP_CHANGE_SUB_GROUP: u16 = 0x27E;
pub const CMSG_REQUEST_PARTY_MEMBER_STATS: u16 = 0x27F;
pub const CMSG_GROUP_SWAP_SUB_GROUP: u16 = 0x280;
pub const CMSG_RESET_FACTION_CHEAT: u16 = 0x281;
pub const CMSG_AUTOSTORE_BANK_ITEM: u16 = 0x282;
pub const CMSG_AUTOBANK_ITEM: u16 = 0x283;
pub const MSG_QUERY_NEXT_MAIL_TIME: u16 = 0x284;
pub const SMSG_RECEIVED_MAIL: u16 = 0x285;
pub const SMSG_RAID_GROUP_ONLY: u16 = 0x286;
pub const CMSG_SET_DURABILITY_CHEAT: u16 = 0x287;
pub const CMSG_SET_PVP_RANK_CHEAT: u16 = 0x288;
pub const CMSG_ADD_PVP_MEDAL_CHEAT: u16 = 0x289;
pub const CMSG_DEL_PVP_MEDAL_CHEAT: u16 = 0x28A;
pub const CMSG_SET_PVP_TITLE: u16 = 0x28B;
pub const SMSG_PVP_CREDIT: u16 = 0x28C;
pub const SMSG_AUCTION_REMOVED_NOTIFICATION: u16 = 0x28D;
pub const CMSG_GROUP_RAID_CONVERT: u16 = 0x28E;
pub const CMSG_GROUP_ASSISTANT_LEADER: u16 = 0x28F;
pub const CMSG_BUYBACK_ITEM: u16 = 0x290;
pub const SMSG_SERVER_MESSAGE: u16 = 0x291;
pub const CMSG_SET_SAVED_INSTANCE_EXTEND: u16 = 0x292;
pub const SMSG_LFG_OFFER_CONTINUE: u16 = 0x293;
pub const CMSG_TEST_DROP_RATE: u16 = 0x294;
pub const SMSG_TEST_DROP_RATE_RESULT: u16 = 0x295;
pub const CMSG_LFG_GET_STATUS: u16 = 0x296;
pub const SMSG_SHOW_MAILBOX: u16 = 0x297;
pub const SMSG_RESET_RANGED_COMBAT_TIMER: u16 = 0x298;
pub const SMSG_CHAT_NOT_IN_PARTY: u16 = 0x299;
pub const CMSG_GMTICKETSYSTEM_TOGGLE: u16 = 0x29A;
pub const CMSG_CANCEL_GROWTH_AURA: u16 = 0x29B;
pub const SMSG_CANCEL_AUTO_REPEAT: u16 = 0x29C;
pub const SMSG_STANDSTATE_UPDATE: u16 = 0x29D;
pub const SMSG_LOOT_ALL_PASSED: u16 = 0x29E;
pub const SMSG_LOOT_ROLL_WON: u16 = 0x29F;
pub const CMSG_LOOT_ROLL: u16 = 0x2A0;
pub const SMSG_LOOT_START_ROLL: u16 = 0x2A1;
pub const SMSG_LOOT_ROLL: u16 = 0x2A2;
pub const CMSG_LOOT_MASTER_GIVE: u16 = 0x2A3;
pub const SMSG_LOOT_MASTER_LIST: u16 = 0x2A4;
pub const SMSG_SET_FORCED_REACTIONS: u16 = 0x2A5;
pub const SMSG_SPELL_FAILED_OTHER: u16 = 0x2A6;
pub const SMSG_GAMEOBJECT_RESET_STATE: u16 = 0x2A7;
pub const CMSG_REPAIR_ITEM: u16 = 0x2A8;
pub const SMSG_CHAT_PLAYER_NOT_FOUND: u16 = 0x2A9;
pub const MSG_TALENT_WIPE_CONFIRM: u16 = 0x2AA;
pub const SMSG_SUMMON_REQUEST: u16 = 0x2AB;
pub const CMSG_SUMMON_RESPONSE: u16 = 0x2AC;
pub const MSG_DEV_SHOWLABEL: u16 = 0x2AD;
pub const SMSG_MONSTER_MOVE_TRANSPORT: u16 = 0x2AE;
pub const SMSG_PET_BROKEN: u16 = 0x2AF;
pub const MSG_MOVE_FEATHER_FALL: u16 = 0x2B0;
pub const MSG_MOVE_WATER_WALK: u16 = 0x2B1;
pub const CMSG_SERVER_BROADCAST: u16 = 0x2B2;
pub const CMSG_SELF_RES: u16 = 0x2B3;
pub const SMSG_FEIGN_DEATH_RESISTED: u16 = 0x2B4;
pub const CMSG_RUN_SCRIPT: u16 = 0x2B5;
pub const SMSG_SCRIPT_MESSAGE: u16 = 0x2B6;
pub const SMSG_DUEL_COUNTDOWN: u16 = 0x2B7;
pub const SMSG_AREA_TRIGGER_MESSAGE: u16 = 0x2B8;
pub const CMSG_SHOWING_HELM: u16 = 0x2B9;
pub const CMSG_SHOWING_CLOAK: u16 = 0x2BA;
pub const SMSG_ROLE_CHOSEN: u16 = 0x2BB;
pub const SMSG_PLAYER_SKINNED: u16 = 0x2BC;
pub const SMSG_DURABILITY_DAMAGE_DEATH: u16 = 0x2BD;
pub const CMSG_SET_EXPLORATION: u16 = 0x2BE;
pub const CMSG_SET_ACTIONBAR_TOGGLES: u16 = 0x2BF;
pub const UMSG_DELETE_GUILD_CHARTER: u16 = 0x2C0;
pub const MSG_PETITION_RENAME: u16 = 0x2C1;
pub const SMSG_INIT_WORLD_STATES: u16 = 0x2C2;
pub const SMSG_UPDATE_WORLD_STATE: u16 = 0x2C3;
pub const CMSG_ITEM_NAME_QUERY: u16 = 0x2C4;
pub const SMSG_ITEM_NAME_QUERY_RESPONSE: u16 = 0x2C5;
pub const SMSG_PET_ACTION_FEEDBACK: u16 = 0x2C6;
pub const CMSG_CHAR_RENAME: u16 = 0x2C7;
pub const SMSG_CHAR_RENAME: u16 = 0x2C8;
pub const CMSG_MOVE_SPLINE_DONE: u16 = 0x2C9;
pub const CMSG_MOVE_FALL_RESET: u16 = 0x2CA;
pub const SMSG_INSTANCE_SAVE_CREATED: u16 = 0x2CB;
pub const SMSG_RAID_INSTANCE_INFO: u16 = 0x2CC;
pub const CMSG_REQUEST_RAID_INFO: u16 = 0x2CD;
pub const CMSG_MOVE_TIME_SKIPPED: u16 = 0x2CE;
pub const CMSG_MOVE_FEATHER_FALL_ACK: u16 = 0x2CF;
pub const CMSG_MOVE_WATER_WALK_ACK: u16 = 0x2D0;
pub const CMSG_MOVE_NOT_ACTIVE_MOVER: u16 = 0x2D1;
pub const SMSG_PLAY_SOUND: u16 = 0x2D2;
pub const CMSG_BATTLEFIELD_STATUS: u16 = 0x2D3;
pub const SMSG_BATTLEFIELD_STATUS: u16 = 0x2D4;
pub const CMSG_BATTLEFIELD_PORT: u16 = 0x2D5;
pub const MSG_INSPECT_HONOR_STATS: u16 = 0x2D6;
pub const CMSG_BATTLEMASTER_HELLO: u16 = 0x2D7;
pub const CMSG_MOVE_START_SWIM_CHEAT: u16 = 0x2D8;
pub const CMSG_MOVE_STOP_SWIM_CHEAT: u16 = 0x2D9;
pub const SMSG_FORCE_WALK_SPEED_CHANGE: u16 = 0x2DA;
pub const CMSG_FORCE_WALK_SPEED_CHANGE_ACK: u16 = 0x2DB;
pub const SMSG_FORCE_SWIM_BACK_SPEED_CHANGE: u16 = 0x2DC;
pub const CMSG_FORCE_SWIM_BACK_SPEED_CHANGE_ACK: u16 = 0x2DD;
pub const SMSG_FORCE_TURN_RATE_CHANGE: u16 = 0x2DE;
pub const CMSG_FORCE_TURN_RATE_CHANGE_ACK: u16 = 0x2DF;
pub const MSG_PVP_LOG_DATA: u16 = 0x2E0;
pub const CMSG_LEAVE_BATTLEFIELD: u16 = 0x2E1;
pub const CMSG_AREA_SPIRIT_HEALER_QUERY: u16 = 0x2E2;
pub const CMSG_AREA_SPIRIT_HEALER_QUEUE: u16 = 0x2E3;
pub const SMSG_AREA_SPIRIT_HEALER_TIME: u16 = 0x2E4;
pub const CMSG_GM_UNTEACH: u16 = 0x2E5;
pub const SMSG_WARDEN_DATA: u16 = 0x2E6;
pub const CMSG_WARDEN_DATA: u16 = 0x2E7;
pub const SMSG_GROUP_JOINED_BATTLEGROUND: u16 = 0x2E8;
pub const MSG_BATTLEGROUND_PLAYER_POSITIONS: u16 = 0x2E9;
pub const CMSG_PET_STOP_ATTACK: u16 = 0x2EA;
pub const SMSG_BINDER_CONFIRM: u16 = 0x2EB;
pub const SMSG_BATTLEGROUND_PLAYER_JOINED: u16 = 0x2EC;
pub const SMSG_BATTLEGROUND_PLAYER_LEFT: u16 = 0x2ED;
pub const CMSG_BATTLEMASTER_JOIN: u16 = 0x2EE;
pub const SMSG_ADDON_INFO: u16 = 0x2EF;
pub const CMSG_PET_UNLEARN: u16 = 0x2F0;
pub const SMSG_PET_UNLEARN_CONFIRM: u16 = 0x2F1;
pub const SMSG_PARTY_MEMBER_STATS_FULL: u16 = 0x2F2;
pub const CMSG_PET_SPELL_AUTOCAST: u16 = 0x2F3;
pub const SMSG_WEATHER: u16 = 0x2F4;
pub const SMSG_PLAY_TIME_WARNING: u16 = 0x2F5;
pub const SMSG_MINIGAME_SETUP: u16 = 0x2F6;
pub const SMSG_MINIGAME_STATE: u16 = 0x2F7;
pub const CMSG_MINIGAME_MOVE: u16 = 0x2F8;
pub const SMSG_MINIGAME_MOVE_FAILED: u16 = 0x2F9;
pub const SMSG_RAID_INSTANCE_MESSAGE: u16 = 0x2FA;
pub const SMSG_COMPRESSED_MOVES: u16 = 0x2FB;
pub const CMSG_GUILD_INFO_TEXT: u16 = 0x2FC;
pub const SMSG_CHAT_RESTRICTED: u16 = 0x2FD;
pub const SMSG_SPLINE_SET_RUN_SPEED: u16 = 0x2FE;
pub const SMSG_SPLINE_SET_RUN_BACK_SPEED: u16 = 0x2FF;
pub const SMSG_SPLINE_SET_SWIM_SPEED: u16 = 0x300;
pub const SMSG_SPLINE_SET_WALK_SPEED: u16 = 0x301;
pub const SMSG_SPLINE_SET_SWIM_BACK_SPEED: u16 = 0x302;
pub const SMSG_SPLINE_SET_TURN_RATE: u16 = 0x303;
pub const SMSG_SPLINE_MOVE_UNROOT: u16 = 0x304;
pub const SMSG_SPLINE_MOVE_FEATHER_FALL: u16 = 0x305;
pub const SMSG_SPLINE_MOVE_NORMAL_FALL: u16 = 0x306;
pub const SMSG_SPLINE_MOVE_SET_HOVER: u16 = 0x307;
pub const SMSG_SPLINE_MOVE_UNSET_HOVER: u16 = 0x308;
pub const SMSG_SPLINE_MOVE_WATER_WALK: u16 = 0x309;
pub const SMSG_SPLINE_MOVE_LAND_WALK: u16 = 0x30A;
pub const SMSG_SPLINE_MOVE_START_SWIM: u16 = 0x30B;
pub const SMSG_SPLINE_MOVE_STOP_SWIM: u16 = 0x30C;
pub const SMSG_SPLINE_MOVE_SET_RUN_MODE: u16 = 0x30D;
pub const SMSG_SPLINE_MOVE_SET_WALK_MODE: u16 = 0x30E;
pub const CMSG_GM_NUKE_ACCOUNT: u16 = 0x30F;
pub const MSG_GM_DESTROY_CORPSE: u16 = 0x310;
pub const CMSG_GM_DESTROY_ONLINE_CORPSE: u16 = 0x311;
pub const CMSG_ACTIVATETAXIEXPRESS: u16 = 0x312;
pub const SMSG_SET_FACTION_ATWAR: u16 = 0x313;
pub const SMSG_GAMETIMEBIAS_SET: u16 = 0x314;
pub const CMSG_DEBUG_ACTIONS_START: u16 = 0x315;
pub const CMSG_DEBUG_ACTIONS_STOP: u16 = 0x316;
pub const CMSG_SET_FACTION_INACTIVE: u16 = 0x317;
pub const CMSG_SET_WATCHED_FACTION: u16 = 0x318;
pub const MSG_MOVE_TIME_SKIPPED: u16 = 0x319;
pub const SMSG_SPLINE_MOVE_ROOT: u16 = 0x31A;
pub const CMSG_SET_EXPLORATION_ALL: u16 = 0x31B;
pub const SMSG_INVALIDATE_PLAYER: u16 = 0x31C;
pub const CMSG_RESET_INSTANCES: u16 = 0x31D;
pub const SMSG_INSTANCE_RESET: u16 = 0x31E;
pub const SMSG_INSTANCE_RESET_FAILED: u16 = 0x31F;
pub const SMSG_UPDATE_LAST_INSTANCE: u16 = 0x320;
pub const MSG_RAID_TARGET_UPDATE: u16 = 0x321;
pub const MSG_RAID_READY_CHECK: u16 = 0x322;
pub const CMSG_LUA_USAGE: u16 = 0x323;
pub const SMSG_PET_ACTION_SOUND: u16 = 0x324;
pub const SMSG_PET_DISMISS_SOUND: u16 = 0x325;
pub const SMSG_GHOSTEE_GONE: u16 = 0x326;
pub const CMSG_GM_UPDATE_TICKET_STATUS: u16 = 0x327;
pub const SMSG_GM_TICKET_STATUS_UPDATE: u16 = 0x328;
pub const MSG_SET_DUNGEON_DIFFICULTY: u16 = 0x329;
pub const CMSG_GMSURVEY_SUBMIT: u16 = 0x32A;
pub const SMSG_UPDATE_INSTANCE_OWNERSHIP: u16 = 0x32B;
pub const CMSG_IGNORE_KNOCKBACK_CHEAT: u16 = 0x32C;
pub const SMSG_CHAT_PLAYER_AMBIGUOUS: u16 = 0x32D;
pub const MSG_DELAY_GHOST_TELEPORT: u16 = 0x32E;
pub const SMSG_SPELLINSTAKILLLOG: u16 = 0x32F;
pub const SMSG_SPELL_UPDATE_CHAIN_TARGETS: u16 = 0x330;
pub const CMSG_CHAT_FILTERED: u16 = 0x331;
pub const SMSG_EXPECTED_SPAM_RECORDS: u16 = 0x332;
pub const SMSG_SPELLSTEALLOG: u16 = 0x333;
pub const CMSG_LOTTERY_QUERY_OBSOLETE: u16 = 0x334;
pub const SMSG_LOTTERY_QUERY_RESULT_OBSOLETE: u16 = 0x335;
pub const CMSG_BUY_LOTTERY_TICKET_OBSOLETE: u16 = 0x336;
pub const SMSG_LOTTERY_RESULT_OBSOLETE: u16 = 0x337;
pub const SMSG_CHARACTER_PROFILE: u16 = 0x338;
pub const SMSG_CHARACTER_PROFILE_REALM_CONNECTED: u16 = 0x339;
pub const SMSG_DEFENSE_MESSAGE: u16 = 0x33A;
pub const SMSG_INSTANCE_DIFFICULTY: u16 = 0x33B;
pub const MSG_GM_RESETINSTANCELIMIT: u16 = 0x33C;
pub const SMSG_MOTD: u16 = 0x33D;
pub const SMSG_MOVE_SET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY: u16 = 0x33E;
pub const SMSG_MOVE_UNSET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY: u16 = 0x33F;
pub const CMSG_MOVE_SET_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY_ACK: u16 = 0x340;
pub const MSG_MOVE_START_SWIM_CHEAT: u16 = 0x341;
pub const MSG_MOVE_STOP_SWIM_CHEAT: u16 = 0x342;
pub const SMSG_MOVE_SET_CAN_FLY: u16 = 0x343;
pub const SMSG_MOVE_UNSET_CAN_FLY: u16 = 0x344;
pub const CMSG_MOVE_SET_CAN_FLY_ACK: u16 = 0x345;
pub const CMSG_MOVE_SET_FLY: u16 = 0x346;
pub const CMSG_SOCKET_GEMS: u16 = 0x347;
pub const CMSG_ARENA_TEAM_CREATE: u16 = 0x348;
pub const SMSG_ARENA_TEAM_COMMAND_RESULT: u16 = 0x349;
pub const MSG_MOVE_UPDATE_CAN_TRANSITION_BETWEEN_SWIM_AND_FLY: u16 = 0x34A;
pub const CMSG_ARENA_TEAM_QUERY: u16 = 0x34B;
pub const SMSG_ARENA_TEAM_QUERY_RESPONSE: u16 = 0x34C;
pub const CMSG_ARENA_TEAM_ROSTER: u16 = 0x34D;
pub const SMSG_ARENA_TEAM_ROSTER: u16 = 0x34E;
pub const CMSG_ARENA_TEAM_INVITE: u16 = 0x34F;
pub const SMSG_ARENA_TEAM_INVITE: u16 = 0x350;
pub const CMSG_ARENA_TEAM_ACCEPT: u16 = 0x351;
pub const CMSG_ARENA_TEAM_DECLINE: u16 = 0x352;
pub const CMSG_ARENA_TEAM_LEAVE: u16 = 0x353;
pub const CMSG_ARENA_TEAM_REMOVE: u16 = 0x354;
pub const CMSG_ARENA_TEAM_DISBAND: u16 = 0x355;
pub const CMSG_ARENA_TEAM_LEADER: u16 = 0x356;
pub const SMSG_ARENA_TEAM_EVENT: u16 = 0x357;
pub const CMSG_BATTLEMASTER_JOIN_ARENA: u16 = 0x358;
pub const MSG_MOVE_START_ASCEND: u16 = 0x359;
pub const MSG_MOVE_STOP_ASCEND: u16 = 0x35A;
pub const SMSG_ARENA_TEAM_STATS: u16 = 0x35B;
pub const CMSG_LFG_JOIN: u16 = 0x35C;
pub const CMSG_LFG_LEAVE: u16 = 0x35D;
pub const CMSG_LFG_SEARCH_JOIN: u16 = 0x35E;
pub const CMSG_LFG_SEARCH_LEAVE: u16 = 0x35F;
pub const SMSG_LFG_SEARCH_RESULTS: u16 = 0x360;
pub const SMSG_LFG_PROPOSAL_UPDATE: u16 = 0x361;
pub const CMSG_LFG_PROPOSAL_RESPONSE: u16 = 0x362;
pub const SMSG_LFG_ROLE_CHECK_UPDATE: u16 = 0x363;
pub const SMSG_LFG_JOIN_RESULT: u16 = 0x364;
pub const SMSG_LFG_QUEUE_STATUS: u16 = 0x365;
pub const CMSG_SET_LFG_COMMENT: u16 = 0x366;
pub const SMSG_LFG_UPDATE_PLAYER: u16 = 0x367;
pub const SMSG_LFG_UPDATE_PARTY: u16 = 0x368;
pub const SMSG_LFG_UPDATE_SEARCH: u16 = 0x369;
pub const CMSG_LFG_SET_ROLES: u16 = 0x36A;
pub const CMSG_LFG_SET_NEEDS: u16 = 0x36B;
pub const CMSG_LFG_BOOT_PLAYER_VOTE: u16 = 0x36C;
pub const SMSG_LFG_BOOT_PLAYER: u16 = 0x36D;
pub const CMSG_LFG_GET_PLAYER_INFO: u16 = 0x36E;
pub const SMSG_LFG_PLAYER_INFO: u16 = 0x36F;
pub const CMSG_LFG_TELEPORT: u16 = 0x370;
pub const CMSG_LFG_GET_PARTY_INFO: u16 = 0x371;
pub const SMSG_LFG_PARTY_INFO: u16 = 0x372;
pub const SMSG_TITLE_EARNED: u16 = 0x373;
pub const CMSG_SET_TITLE: u16 = 0x374;
pub const CMSG_CANCEL_MOUNT_AURA: u16 = 0x375;
pub const SMSG_ARENA_ERROR: u16 = 0x376;
pub const MSG_INSPECT_ARENA_TEAMS: u16 = 0x377;
pub const SMSG_DEATH_RELEASE_LOC: u16 = 0x378;
pub const CMSG_CANCEL_TEMP_ENCHANTMENT: u16 = 0x379;
pub const SMSG_FORCED_DEATH_UPDATE: u16 = 0x37A;
pub const CMSG_CHEAT_SET_HONOR_CURRENCY: u16 = 0x37B;
pub const CMSG_CHEAT_SET_ARENA_CURRENCY: u16 = 0x37C;
pub const MSG_MOVE_SET_FLIGHT_SPEED_CHEAT: u16 = 0x37D;
pub const MSG_MOVE_SET_FLIGHT_SPEED: u16 = 0x37E;
pub const MSG_MOVE_SET_FLIGHT_BACK_SPEED_CHEAT: u16 = 0x37F;
pub const MSG_MOVE_SET_FLIGHT_BACK_SPEED: u16 = 0x380;
pub const SMSG_FORCE_FLIGHT_SPEED_CHANGE: u16 = 0x381;
pub const CMSG_FORCE_FLIGHT_SPEED_CHANGE_ACK: u16 = 0x382;
pub const SMSG_FORCE_FLIGHT_BACK_SPEED_CHANGE: u16 = 0x383;
pub const CMSG_FORCE_FLIGHT_BACK_SPEED_CHANGE_ACK: u16 = 0x384;
pub const SMSG_SPLINE_SET_FLIGHT_SPEED: u16 = 0x385;
pub const SMSG_SPLINE_SET_FLIGHT_BACK_SPEED: u16 = 0x386;
pub const CMSG_MAELSTROM_INVALIDATE_CACHE: u16 = 0x387;
pub const SMSG_FLIGHT_SPLINE_SYNC: u16 = 0x388;
pub const CMSG_SET_TAXI_BENCHMARK_MODE: u16 = 0x389;
pub const SMSG_JOINED_BATTLEGROUND_QUEUE: u16 = 0x38A;
pub const SMSG_REALM_SPLIT: u16 = 0x38B;
pub const CMSG_REALM_SPLIT: u16 = 0x38C;
pub const CMSG_MOVE_CHNG_TRANSPORT: u16 = 0x38D;
pub const MSG_PARTY_ASSIGNMENT: u16 = 0x38E;
pub const SMSG_OFFER_PETITION_ERROR: u16 = 0x38F;
pub const SMSG_TIME_SYNC_REQ: u16 = 0x390;
pub const CMSG_TIME_SYNC_RESP: u16 = 0x391;
pub const CMSG_SEND_LOCAL_EVENT: u16 = 0x392;
pub const CMSG_SEND_GENERAL_TRIGGER: u16 = 0x393;
pub const CMSG_SEND_COMBAT_TRIGGER: u16 = 0x394;
pub const CMSG_MAELSTROM_GM_SENT_MAIL: u16 = 0x395;
pub const SMSG_RESET_FAILED_NOTIFY: u16 = 0x396;
pub const SMSG_REAL_GROUP_UPDATE: u16 = 0x397;
pub const SMSG_LFG_DISABLED: u16 = 0x398;
pub const CMSG_ACTIVE_PVP_CHEAT: u16 = 0x399;
pub const CMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY: u16 = 0x39A;
pub const SMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY_RESPONSE: u16 = 0x39B;
pub const SMSG_CHEAT_DUMP_ITEMS_DEBUG_ONLY_RESPONSE_WRITE_FILE: u16 = 0x39C;
pub const SMSG_UPDATE_COMBO_POINTS: u16 = 0x39D;
pub const SMSG_VOICE_SESSION_ROSTER_UPDATE: u16 = 0x39E;
pub const SMSG_VOICE_SESSION_LEAVE: u16 = 0x39F;
pub const SMSG_VOICE_SESSION_ADJUST_PRIORITY: u16 = 0x3A0;
pub const CMSG_VOICE_SET_TALKER_MUTED_REQUEST: u16 = 0x3A1;
pub const SMSG_VOICE_SET_TALKER_MUTED: u16 = 0x3A2;
pub const SMSG_INIT_EXTRA_AURA_INFO_OBSOLETE: u16 = 0x3A3;
pub const SMSG_SET_EXTRA_AURA_INFO_OBSOLETE: u16 = 0x3A4;
pub const SMSG_SET_EXTRA_AURA_INFO_NEED_UPDATE_OBSOLETE: u16 = 0x3A5;
pub const SMSG_CLEAR_EXTRA_AURA_INFO_OBSOLETE: u16 = 0x3A6;
pub const MSG_MOVE_START_DESCEND: u16 = 0x3A7;
pub const CMSG_IGNORE_REQUIREMENTS_CHEAT: u16 = 0x3A8;
pub const SMSG_IGNORE_REQUIREMENTS_CHEAT: u16 = 0x3A9;
pub const SMSG_SPELL_CHANCE_PROC_LOG: u16 = 0x3AA;
pub const CMSG_MOVE_SET_RUN_SPEED: u16 = 0x3AB;
pub const SMSG_DISMOUNT: u16 = 0x3AC;
pub const MSG_MOVE_UPDATE_CAN_FLY: u16 = 0x3AD;
pub const MSG_RAID_READY_CHECK_CONFIRM: u16 = 0x3AE;
pub const CMSG_VOICE_SESSION_ENABLE: u16 = 0x3AF;
pub const SMSG_VOICE_SESSION_ENABLE: u16 = 0x3B0;
pub const SMSG_VOICE_PARENTAL_CONTROLS: u16 = 0x3B1;
pub const CMSG_GM_WHISPER: u16 = 0x3B2;
pub const SMSG_GM_MESSAGECHAT: u16 = 0x3B3;
pub const MSG_GM_GEARRATING: u16 = 0x3B4;
pub const CMSG_COMMENTATOR_ENABLE: u16 = 0x3B5;
pub const SMSG_COMMENTATOR_STATE_CHANGED: u16 = 0x3B6;
pub const CMSG_COMMENTATOR_GET_MAP_INFO: u16 = 0x3B7;
pub const SMSG_COMMENTATOR_MAP_INFO: u16 = 0x3B8;
pub const CMSG_COMMENTATOR_GET_PLAYER_INFO: u16 = 0x3B9;
pub const SMSG_COMMENTATOR_GET_PLAYER_INFO: u16 = 0x3BA;
pub const SMSG_COMMENTATOR_PLAYER_INFO: u16 = 0x3BB;
pub const CMSG_COMMENTATOR_ENTER_INSTANCE: u16 = 0x3BC;
pub const CMSG_COMMENTATOR_EXIT_INSTANCE: u16 = 0x3BD;
pub const CMSG_COMMENTATOR_INSTANCE_COMMAND: u16 = 0x3BE;
pub const SMSG_CLEAR_TARGET: u16 = 0x3BF;
pub const CMSG_BOT_DETECTED: u16 = 0x3C0;
pub const SMSG_CROSSED_INEBRIATION_THRESHOLD: u16 = 0x3C1;
pub const CMSG_CHEAT_PLAYER_LOGIN: u16 = 0x3C2;
pub const CMSG_CHEAT_PLAYER_LOOKUP: u16 = 0x3C3;
pub const SMSG_CHEAT_PLAYER_LOOKUP: u16 = 0x3C4;
pub const SMSG_KICK_REASON: u16 = 0x3C5;
pub const MSG_RAID_READY_CHECK_FINISHED: u16 = 0x3C6;
pub const CMSG_COMPLAIN: u16 = 0x3C7;
pub const SMSG_COMPLAIN_RESULT: u16 = 0x3C8;
pub const SMSG_FEATURE_SYSTEM_STATUS: u16 = 0x3C9;
pub const CMSG_GM_SHOW_COMPLAINTS: u16 = 0x3CA;
pub const CMSG_GM_UNSQUELCH: u16 = 0x3CB;
pub const CMSG_CHANNEL_SILENCE_VOICE: u16 = 0x3CC;
pub const CMSG_CHANNEL_SILENCE_ALL: u16 = 0x3CD;
pub const CMSG_CHANNEL_UNSILENCE_VOICE: u16 = 0x3CE;
pub const CMSG_CHANNEL_UNSILENCE_ALL: u16 = 0x3CF;
pub const CMSG_TARGET_CAST: u16 = 0x3D0;
pub const CMSG_TARGET_SCRIPT_CAST: u16 = 0x3D1;
pub const CMSG_CHANNEL_DISPLAY_LIST: u16 = 0x3D2;
pub const CMSG_SET_ACTIVE_VOICE_CHANNEL: u16 = 0x3D3;
pub const CMSG_GET_CHANNEL_MEMBER_COUNT: u16 = 0x3D4;
pub const SMSG_CHANNEL_MEMBER_COUNT: u16 = 0x3D5;
pub const CMSG_CHANNEL_VOICE_ON: u16 = 0x3D6;
pub const CMSG_CHANNEL_VOICE_OFF: u16 = 0x3D7;
pub const CMSG_DEBUG_LIST_TARGETS: u16 = 0x3D8;
pub const SMSG_DEBUG_LIST_TARGETS: u16 = 0x3D9;
pub const SMSG_AVAILABLE_VOICE_CHANNEL: u16 = 0x3DA;
pub const CMSG_ADD_VOICE_IGNORE: u16 = 0x3DB;
pub const CMSG_DEL_VOICE_IGNORE: u16 = 0x3DC;
pub const CMSG_PARTY_SILENCE: u16 = 0x3DD;
pub const CMSG_PARTY_UNSILENCE: u16 = 0x3DE;
pub const MSG_NOTIFY_PARTY_SQUELCH: u16 = 0x3DF;
pub const SMSG_COMSAT_RECONNECT_TRY: u16 = 0x3E0;
pub const SMSG_COMSAT_DISCONNECT: u16 = 0x3E1;
pub const SMSG_COMSAT_CONNECT_FAIL: u16 = 0x3E2;
pub const SMSG_VOICE_CHAT_STATUS: u16 = 0x3E3;
pub const CMSG_REPORT_PVP_AFK: u16 = 0x3E4;
pub const SMSG_REPORT_PVP_AFK_RESULT: u16 = 0x3E5;
pub const CMSG_GUILD_BANKER_ACTIVATE: u16 = 0x3E6;
pub const CMSG_GUILD_BANK_QUERY_TAB: u16 = 0x3E7;
pub const SMSG_GUILD_BANK_LIST: u16 = 0x3E8;
pub const CMSG_GUILD_BANK_SWAP_ITEMS: u16 = 0x3E9;
pub const CMSG_GUILD_BANK_BUY_TAB: u16 = 0x3EA;
pub const CMSG_GUILD_BANK_UPDATE_TAB: u16 = 0x3EB;
pub const CMSG_GUILD_BANK_DEPOSIT_MONEY: u16 = 0x3EC;
pub const CMSG_GUILD_BANK_WITHDRAW_MONEY: u16 = 0x3ED;
pub const MSG_GUILD_BANK_LOG_QUERY: u16 = 0x3EE;
pub const CMSG_SET_CHANNEL_WATCH: u16 = 0x3EF;
pub const SMSG_USERLIST_ADD: u16 = 0x3F0;
pub const SMSG_USERLIST_REMOVE: u16 = 0x3F1;
pub const SMSG_USERLIST_UPDATE: u16 = 0x3F2;
pub const CMSG_CLEAR_CHANNEL_WATCH: u16 = 0x3F3;
pub const SMSG_INSPECT_RESULTS: u16 = 0x3F4;
pub const SMSG_GOGOGO_OBSOLETE: u16 = 0x3F5;
pub const SMSG_ECHO_PARTY_SQUELCH: u16 = 0x3F6;
pub const CMSG_SET_TITLE_SUFFIX: u16 = 0x3F7;
pub const CMSG_SPELLCLICK: u16 = 0x3F8;
pub const SMSG_LOOT_LIST: u16 = 0x3F9;
pub const CMSG_GM_CHARACTER_RESTORE: u16 = 0x3FA;
pub const CMSG_GM_CHARACTER_SAVE: u16 = 0x3FB;
pub const SMSG_VOICESESSION_FULL: u16 = 0x3FC;
pub const MSG_GUILD_PERMISSIONS: u16 = 0x3FD;
pub const MSG_GUILD_BANK_MONEY_WITHDRAWN: u16 = 0x3FE;
pub const MSG_GUILD_EVENT_LOG_QUERY: u16 = 0x3FF;
pub const CMSG_MAELSTROM_RENAME_GUILD: u16 = 0x400;
pub const CMSG_GET_MIRRORIMAGE_DATA: u16 = 0x401;
pub const SMSG_MIRRORIMAGE_DATA: u16 = 0x402;
pub const SMSG_FORCE_DISPLAY_UPDATE: u16 = 0x403;
pub const SMSG_SPELL_CHANCE_RESIST_PUSHBACK: u16 = 0x404;
pub const CMSG_IGNORE_DIMINISHING_RETURNS_CHEAT: u16 = 0x405;
pub const SMSG_IGNORE_DIMINISHING_RETURNS_CHEAT: u16 = 0x406;
pub const CMSG_KEEP_ALIVE: u16 = 0x407;
pub const SMSG_RAID_READY_CHECK_ERROR: u16 = 0x408;
pub const CMSG_OPT_OUT_OF_LOOT: u16 = 0x409;
pub const MSG_QUERY_GUILD_BANK_TEXT: u16 = 0x40A;
pub const CMSG_SET_GUILD_BANK_TEXT: u16 = 0x40B;
pub const CMSG_SET_GRANTABLE_LEVELS: u16 = 0x40C;
pub const CMSG_GRANT_LEVEL: u16 = 0x40D;
pub const CMSG_REFER_A_FRIEND: u16 = 0x40E;
pub const MSG_GM_CHANGE_ARENA_RATING: u16 = 0x40F;
pub const CMSG_DECLINE_CHANNEL_INVITE: u16 = 0x410;
pub const SMSG_GROUPACTION_THROTTLED: u16 = 0x411;
pub const SMSG_OVERRIDE_LIGHT: u16 = 0x412;
pub const SMSG_TOTEM_CREATED: u16 = 0x413;
pub const CMSG_TOTEM_DESTROYED: u16 = 0x414;
pub const CMSG_EXPIRE_RAID_INSTANCE: u16 = 0x415;
pub const CMSG_NO_SPELL_VARIANCE: u16 = 0x416;
pub const CMSG_QUESTGIVER_STATUS_MULTIPLE_QUERY: u16 = 0x417;
pub const SMSG_QUESTGIVER_STATUS_MULTIPLE: u16 = 0x418;
pub const CMSG_SET_PLAYER_DECLINED_NAMES: u16 = 0x419;
pub const SMSG_SET_PLAYER_DECLINED_NAMES_RESULT: u16 = 0x41A;
pub const CMSG_QUERY_SERVER_BUCK_DATA: u16 = 0x41B;
pub const CMSG_CLEAR_SERVER_BUCK_DATA: u16 = 0x41C;
pub const SMSG_SERVER_BUCK_DATA: u16 = 0x41D;
pub const SMSG_SEND_UNLEARN_SPELLS: u16 = 0x41E;
pub const SMSG_PROPOSE_LEVEL_GRANT: u16 = 0x41F;
pub const CMSG_ACCEPT_LEVEL_GRANT: u16 = 0x420;
pub const SMSG_REFER_A_FRIEND_FAILURE: u16 = 0x421;
pub const SMSG_SPLINE_MOVE_SET_FLYING: u16 = 0x422;
pub const SMSG_SPLINE_MOVE_UNSET_FLYING: u16 = 0x423;
pub const SMSG_SUMMON_CANCEL: u16 = 0x424;
pub const CMSG_CHANGE_PERSONAL_ARENA_RATING: u16 = 0x425;
pub const CMSG_ALTER_APPEARANCE: u16 = 0x426;
pub const SMSG_ENABLE_BARBER_SHOP: u16 = 0x427;
pub const SMSG_BARBER_SHOP_RESULT: u16 = 0x428;
pub const CMSG_CALENDAR_GET_CALENDAR: u16 = 0x429;
pub const CMSG_CALENDAR_GET_EVENT: u16 = 0x42A;
pub const CMSG_CALENDAR_GUILD_FILTER: u16 = 0x42B;
pub const CMSG_CALENDAR_ARENA_TEAM: u16 = 0x42C;
pub const CMSG_CALENDAR_ADD_EVENT: u16 = 0x42D;
pub const CMSG_CALENDAR_UPDATE_EVENT: u16 = 0x42E;
pub const CMSG_CALENDAR_REMOVE_EVENT: u16 = 0x42F;
pub const CMSG_CALENDAR_COPY_EVENT: u16 = 0x430;
pub const CMSG_CALENDAR_EVENT_INVITE: u16 = 0x431;
pub const CMSG_CALENDAR_EVENT_RSVP: u16 = 0x432;
pub const CMSG_CALENDAR_EVENT_REMOVE_INVITE: u16 = 0x433;
pub const CMSG_CALENDAR_EVENT_STATUS: u16 = 0x434;
pub const CMSG_CALENDAR_EVENT_MODERATOR_STATUS: u16 = 0x435;
pub const SMSG_CALENDAR_SEND_CALENDAR: u16 = 0x436;
pub const SMSG_CALENDAR_SEND_EVENT: u16 = 0x437;
pub const SMSG_CALENDAR_FILTER_GUILD: u16 = 0x438;
pub const SMSG_CALENDAR_ARENA_TEAM: u16 = 0x439;
pub const SMSG_CALENDAR_EVENT_INVITE: u16 = 0x43A;
pub const SMSG_CALENDAR_EVENT_INVITE_REMOVED: u16 = 0x43B;
pub const SMSG_CALENDAR_EVENT_STATUS: u16 = 0x43C;
pub const SMSG_CALENDAR_COMMAND_RESULT: u16 = 0x43D;
pub const SMSG_CALENDAR_RAID_LOCKOUT_ADDED: u16 = 0x43E;
pub const SMSG_CALENDAR_RAID_LOCKOUT_REMOVED: u16 = 0x43F;
pub const SMSG_CALENDAR_EVENT_INVITE_ALERT: u16 = 0x440;
pub const SMSG_CALENDAR_EVENT_INVITE_REMOVED_ALERT: u16 = 0x441;
pub const SMSG_CALENDAR_EVENT_INVITE_STATUS_ALERT: u16 = 0x442;
pub const SMSG_CALENDAR_EVENT_REMOVED_ALERT: u16 = 0x443;
pub const SMSG_CALENDAR_EVENT_UPDATED_ALERT: u16 = 0x444;
pub const SMSG_CALENDAR_EVENT_MODERATOR_STATUS_ALERT: u16 = 0x445;
pub const CMSG_CALENDAR_COMPLAIN: u16 = 0x446;
pub const CMSG_CALENDAR_GET_NUM_PENDING: u16 = 0x447;
pub const SMSG_CALENDAR_SEND_NUM_PENDING: u16 = 0x448;
pub const CMSG_SAVE_DANCE: u16 = 0x449;
pub const SMSG_NOTIFY_DANCE: u16 = 0x44A;
pub const CMSG_PLAY_DANCE: u16 = 0x44B;
pub const SMSG_PLAY_DANCE: u16 = 0x44C;
pub const CMSG_LOAD_DANCES: u16 = 0x44D;
pub const CMSG_STOP_DANCE: u16 = 0x44E;
pub const SMSG_STOP_DANCE: u16 = 0x44F;
pub const CMSG_SYNC_DANCE: u16 = 0x450;
pub const CMSG_DANCE_QUERY: u16 = 0x451;
pub const SMSG_DANCE_QUERY_RESPONSE: u16 = 0x452;
pub const SMSG_INVALIDATE_DANCE: u16 = 0x453;
pub const CMSG_DELETE_DANCE: u16 = 0x454;
pub const SMSG_LEARNED_DANCE_MOVES: u16 = 0x455;
pub const CMSG_LEARN_DANCE_MOVE: u16 = 0x456;
pub const CMSG_UNLEARN_DANCE_MOVE: u16 = 0x457;
pub const CMSG_SET_RUNE_COUNT: u16 = 0x458;
pub const CMSG_SET_RUNE_COOLDOWN: u16 = 0x459;
pub const MSG_MOVE_SET_PITCH_RATE_CHEAT: u16 = 0x45A;
pub const MSG_MOVE_SET_PITCH_RATE: u16 = 0x45B;
pub const SMSG_FORCE_PITCH_RATE_CHANGE: u16 = 0x45C;
pub const CMSG_FORCE_PITCH_RATE_CHANGE_ACK: u16 = 0x45D;
pub const SMSG_SPLINE_SET_PITCH_RATE: u16 = 0x45E;
pub const CMSG_CALENDAR_EVENT_INVITE_NOTES: u16 = 0x45F;
pub const SMSG_CALENDAR_EVENT_INVITE_NOTES: u16 = 0x460;
pub const SMSG_CALENDAR_EVENT_INVITE_NOTES_ALERT: u16 = 0x461;
pub const CMSG_UPDATE_MISSILE_TRAJECTORY: u16 = 0x462;
pub const SMSG_UPDATE_ACCOUNT_DATA_COMPLETE: u16 = 0x463;
pub const SMSG_TRIGGER_MOVIE: u16 = 0x464;
pub const CMSG_COMPLETE_MOVIE: u16 = 0x465;
pub const CMSG_SET_GLYPH_SLOT: u16 = 0x466;
pub const CMSG_SET_GLYPH: u16 = 0x467;
pub const SMSG_ACHIEVEMENT_EARNED: u16 = 0x468;
pub const SMSG_DYNAMIC_DROP_ROLL_RESULT: u16 = 0x469;
pub const SMSG_CRITERIA_UPDATE: u16 = 0x46A;
pub const CMSG_QUERY_INSPECT_ACHIEVEMENTS: u16 = 0x46B;
pub const SMSG_RESPOND_INSPECT_ACHIEVEMENTS: u16 = 0x46C;
pub const CMSG_DISMISS_CONTROLLED_VEHICLE: u16 = 0x46D;
pub const CMSG_COMPLETE_ACHIEVEMENT_CHEAT: u16 = 0x46E;
pub const SMSG_QUESTUPDATE_ADD_PVP_KILL: u16 = 0x46F;
pub const CMSG_SET_CRITERIA_CHEAT: u16 = 0x470;
pub const SMSG_CALENDAR_RAID_LOCKOUT_UPDATED: u16 = 0x471;
pub const CMSG_UNITANIMTIER_CHEAT: u16 = 0x472;
pub const CMSG_CHAR_CUSTOMIZE: u16 = 0x473;
pub const SMSG_CHAR_CUSTOMIZE: u16 = 0x474;
pub const SMSG_PET_RENAMEABLE: u16 = 0x475;
pub const CMSG_REQUEST_VEHICLE_EXIT: u16 = 0x476;
pub const CMSG_REQUEST_VEHICLE_PREV_SEAT: u16 = 0x477;
pub const CMSG_REQUEST_VEHICLE_NEXT_SEAT: u16 = 0x478;
pub const CMSG_REQUEST_VEHICLE_SWITCH_SEAT: u16 = 0x479;
pub const CMSG_PET_LEARN_TALENT: u16 = 0x47A;
pub const CMSG_PET_UNLEARN_TALENTS: u16 = 0x47B;
pub const SMSG_SET_PHASE_SHIFT: u16 = 0x47C;
pub const SMSG_ALL_ACHIEVEMENT_DATA: u16 = 0x47D;
pub const CMSG_FORCE_SAY_CHEAT: u16 = 0x47E;
pub const SMSG_HEALTH_UPDATE: u16 = 0x47F;
pub const SMSG_POWER_UPDATE: u16 = 0x480;
pub const CMSG_GAMEOBJ_REPORT_USE: u16 = 0x481;
pub const SMSG_HIGHEST_THREAT_UPDATE: u16 = 0x482;
pub const SMSG_THREAT_UPDATE: u16 = 0x483;
pub const SMSG_THREAT_REMOVE: u16 = 0x484;
pub const SMSG_THREAT_CLEAR: u16 = 0x485;
pub const SMSG_CONVERT_RUNE: u16 = 0x486;
pub const SMSG_RESYNC_RUNES: u16 = 0x487;
pub const SMSG_ADD_RUNE_POWER: u16 = 0x488;
pub const CMSG_START_QUEST: u16 = 0x489;
pub const CMSG_REMOVE_GLYPH: u16 = 0x48A;
pub const CMSG_DUMP_OBJECTS: u16 = 0x48B;
pub const SMSG_DUMP_OBJECTS_DATA: u16 = 0x48C;
pub const CMSG_DISMISS_CRITTER: u16 = 0x48D;
pub const SMSG_NOTIFY_DEST_LOC_SPELL_CAST: u16 = 0x48E;
pub const CMSG_AUCTION_LIST_PENDING_SALES: u16 = 0x48F;
pub const SMSG_AUCTION_LIST_PENDING_SALES: u16 = 0x490;
pub const SMSG_MODIFY_COOLDOWN: u16 = 0x491;
pub const SMSG_PET_UPDATE_COMBO_POINTS: u16 = 0x492;
pub const CMSG_ENABLETAXI: u16 = 0x493;
pub const SMSG_PRE_RESURRECT: u16 = 0x494;
pub const SMSG_AURA_UPDATE_ALL: u16 = 0x495;
pub const SMSG_AURA_UPDATE: u16 = 0x496;
pub const CMSG_FLOOD_GRACE_CHEAT: u16 = 0x497;
pub const SMSG_SERVER_FIRST_ACHIEVEMENT: u16 = 0x498;
pub const SMSG_PET_LEARNED_SPELL: u16 = 0x499;
pub const SMSG_PET_REMOVED_SPELL: u16 = 0x49A;
pub const CMSG_CHANGE_SEATS_ON_CONTROLLED_VEHICLE: u16 = 0x49B;
pub const CMSG_HEARTH_AND_RESURRECT: u16 = 0x49C;
pub const SMSG_ON_CANCEL_EXPECTED_RIDE_VEHICLE_AURA: u16 = 0x49D;
pub const SMSG_CRITERIA_DELETED: u16 = 0x49E;
pub const SMSG_ACHIEVEMENT_DELETED: u16 = 0x49F;
pub const CMSG_SERVER_INFO_QUERY: u16 = 0x4A0;
pub const SMSG_SERVER_INFO_RESPONSE: u16 = 0x4A1;
pub const CMSG_CHECK_LOGIN_CRITERIA: u16 = 0x4A2;
pub const SMSG_SERVER_BUCK_DATA_START: u16 = 0x4A3;
pub const CMSG_SET_BREATH: u16 = 0x4A4;
pub const CMSG_QUERY_VEHICLE_STATUS: u16 = 0x4A5;
pub const SMSG_BATTLEGROUND_INFO_THROTTLED: u16 = 0x4A6;
pub const SMSG_SET_VEHICLE_REC_ID: u16 = 0x4A7;
pub const CMSG_RIDE_VEHICLE_INTERACT: u16 = 0x4A8;
pub const CMSG_CONTROLLER_EJECT_PASSENGER: u16 = 0x4A9;
pub const SMSG_PET_GUIDS: u16 = 0x4AA;
pub const SMSG_CLIENTCACHE_VERSION: u16 = 0x4AB;
pub const CMSG_CHANGE_GDF_ARENA_RATING: u16 = 0x4AC;
pub const CMSG_SET_ARENA_TEAM_RATING_BY_INDEX: u16 = 0x4AD;
pub const CMSG_SET_ARENA_TEAM_WEEKLY_GAMES: u16 = 0x4AE;
pub const CMSG_SET_ARENA_TEAM_SEASON_GAMES: u16 = 0x4AF;
pub const CMSG_SET_ARENA_MEMBER_WEEKLY_GAMES: u16 = 0x4B0;
pub const CMSG_SET_ARENA_MEMBER_SEASON_GAMES: u16 = 0x4B1;
pub const SMSG_SET_ITEM_PURCHASE_DATA: u16 = 0x4B2;
pub const CMSG_GET_ITEM_PURCHASE_DATA: u16 = 0x4B3;
pub const CMSG_ITEM_PURCHASE_REFUND: u16 = 0x4B4;
pub const SMSG_ITEM_PURCHASE_REFUND_RESULT: u16 = 0x4B5;
pub const CMSG_CORPSE_TRANSPORT_QUERY: u16 = 0x4B6;
pub const SMSG_CORPSE_TRANSPORT_QUERY: u16 = 0x4B7;
pub const CMSG_UNUSED5: u16 = 0x4B8;
pub const CMSG_UNUSED6: u16 = 0x4B9;
pub const CMSG_CALENDAR_EVENT_SIGNUP: u16 = 0x4BA;
pub const SMSG_CALENDAR_CLEAR_PENDING_ACTION: u16 = 0x4BB;
pub const SMSG_LOAD_EQUIPMENT_SET: u16 = 0x4BC;
pub const CMSG_SAVE_EQUIPMENT_SET: u16 = 0x4BD;
pub const CMSG_ON_MISSILE_TRAJECTORY_COLLISION: u16 = 0x4BE;
pub const SMSG_NOTIFY_MISSILE_TRAJECTORY_COLLISION: u16 = 0x4BF;
pub const SMSG_TALENT_UPDATE: u16 = 0x4C0;
pub const CMSG_LEARN_TALENT_GROUP: u16 = 0x4C1;
pub const CMSG_PET_LEARN_TALENT_GROUP: u16 = 0x4C2;
pub const CMSG_SET_ACTIVE_TALENT_GROUP_OBSOLETE: u16 = 0x4C3;
pub const CMSG_GM_GRANT_ACHIEVEMENT: u16 = 0x4C4;
pub const CMSG_GM_REMOVE_ACHIEVEMENT: u16 = 0x4C5;
pub const CMSG_GM_SET_CRITERIA_FOR_PLAYER: u16 = 0x4C6;
pub const SMSG_DESTROY_ARENA_UNIT: u16 = 0x4C7;
pub const SMSG_ARENA_TEAM_CHANGE_FAILED: u16 = 0x4C8;
pub const CMSG_PROFILEDATA_REQUEST: u16 = 0x4C9;
pub const SMSG_PROFILEDATA_RESPONSE: u16 = 0x4CA;
pub const CMSG_START_BATTLEFIELD_CHEAT: u16 = 0x4CB;
pub const CMSG_END_BATTLEFIELD_CHEAT: u16 = 0x4CC;
pub const SMSG_COMPOUND_MOVE: u16 = 0x4CD;
pub const SMSG_MOVE_GRAVITY_DISABLE: u16 = 0x4CE;
pub const CMSG_MOVE_GRAVITY_DISABLE_ACK: u16 = 0x4CF;
pub const SMSG_MOVE_GRAVITY_ENABLE: u16 = 0x4D0;
pub const CMSG_MOVE_GRAVITY_ENABLE_ACK: u16 = 0x4D1;
pub const MSG_MOVE_GRAVITY_CHNG: u16 = 0x4D2;
pub const SMSG_SPLINE_MOVE_GRAVITY_DISABLE: u16 = 0x4D3;
pub const SMSG_SPLINE_MOVE_GRAVITY_ENABLE: u16 = 0x4D4;
pub const CMSG_USE_EQUIPMENT_SET: u16 = 0x4D5;
pub const SMSG_USE_EQUIPMENT_SET_RESULT: u16 = 0x4D6;
pub const CMSG_FORCE_ANIM: u16 = 0x4D7;
pub const SMSG_FORCE_ANIM: u16 = 0x4D8;
pub const CMSG_CHAR_FACTION_CHANGE: u16 = 0x4D9;
pub const SMSG_CHAR_FACTION_CHANGE: u16 = 0x4DA;
pub const CMSG_PVP_QUEUE_STATS_REQUEST: u16 = 0x4DB;
pub const SMSG_PVP_QUEUE_STATS: u16 = 0x4DC;
pub const CMSG_SET_PAID_SERVICE_CHEAT: u16 = 0x4DD;
pub const SMSG_BATTLEFIELD_MANAGER_ENTRY_INVITE: u16 = 0x4DE;
pub const CMSG_BATTLEFIELD_MANAGER_ENTRY_INVITE_RESPONSE: u16 = 0x4DF;
pub const SMSG_BATTLEFIELD_MANAGER_ENTERING: u16 = 0x4E0;
pub const SMSG_BATTLEFIELD_MANAGER_QUEUE_INVITE: u16 = 0x4E1;
pub const CMSG_BATTLEFIELD_MANAGER_QUEUE_INVITE_RESPONSE: u16 = 0x4E2;
pub const CMSG_BATTLEFIELD_MANAGER_QUEUE_REQUEST: u16 = 0x4E3;
pub const SMSG_BATTLEFIELD_MANAGER_QUEUE_REQUEST_RESPONSE: u16 = 0x4E4;
pub const SMSG_BATTLEFIELD_MANAGER_EJECT_PENDING: u16 = 0x4E5;
pub const SMSG_BATTLEFIELD_MANAGER_EJECTED: u16 = 0x4E6;
pub const CMSG_BATTLEFIELD_MANAGER_EXIT_REQUEST: u16 = 0x4E7;
pub const SMSG_BATTLEFIELD_MANAGER_STATE_CHANGED: u16 = 0x4E8;
pub const CMSG_BATTLEFIELD_MANAGER_ADVANCE_STATE: u16 = 0x4E9;
pub const CMSG_BATTLEFIELD_MANAGER_SET_NEXT_TRANSITION_TIME: u16 = 0x4EA;
pub const MSG_SET_RAID_DIFFICULTY: u16 = 0x4EB;
pub const CMSG_XPGAIN: u16 = 0x4EC;
pub const SMSG_XPGAIN: u16 = 0x4ED;
pub const SMSG_GMTICKET_RESPONSE_ERROR: u16 = 0x4EE;
pub const SMSG_GMTICKET_GET_RESPONSE: u16 = 0x4EF;
pub const CMSG_GMTICKET_RESOLVE_RESPONSE: u16 = 0x4F0;
pub const SMSG_GMTICKET_RESOLVE_RESPONSE: u16 = 0x4F1;
pub const SMSG_GMTICKET_CREATE_RESPONSE_TICKET: u16 = 0x4F2;
pub const CMSG_GM_CREATE_TICKET_RESPONSE: u16 = 0x4F3;
pub const CMSG_SERVERINFO: u16 = 0x4F4;
pub const SMSG_SERVERINFO: u16 = 0x4F5;
pub const CMSG_UI_TIME_REQUEST: u16 = 0x4F6;
pub const SMSG_UI_TIME: u16 = 0x4F7;
pub const CMSG_CHAR_RACE_CHANGE: u16 = 0x4F8;
pub const MSG_VIEW_PHASE_SHIFT: u16 = 0x4F9;
pub const SMSG_TALENTS_INVOLUNTARILY_RESET: u16 = 0x4FA;
pub const CMSG_DEBUG_SERVER_GEO: u16 = 0x4FB;
pub const SMSG_DEBUG_SERVER_GEO: u16 = 0x4FC;
pub const SMSG_LOOT_UPDATE: u16 = 0x4FD;
pub const UMSG_UPDATE_GROUP_INFO: u16 = 0x4FE;
pub const CMSG_READY_FOR_ACCOUNT_DATA_TIMES: u16 = 0x4FF;
pub const CMSG_QUERY_GET_ALL_QUESTS: u16 = 0x500;
pub const SMSG_ALL_QUESTS_COMPLETED: u16 = 0x501;
pub const CMSG_GMLAGREPORT_SUBMIT: u16 = 0x502;
pub const CMSG_AFK_MONITOR_INFO_REQUEST: u16 = 0x503;
pub const SMSG_AFK_MONITOR_INFO_RESPONSE: u16 = 0x504;
pub const CMSG_AFK_MONITOR_INFO_CLEAR: u16 = 0x505;
pub const SMSG_AREA_TRIGGER_NO_CORPSE: u16 = 0x506;
pub const CMSG_GM_NUKE_CHARACTER: u16 = 0x507;
pub const CMSG_LOW_LEVEL_RAID: u16 = 0x508;
pub const CMSG_LOW_LEVEL_RAID_USER: u16 = 0x509;
pub const SMSG_CAMERA_SHAKE: u16 = 0x50A;
pub const SMSG_SOCKET_GEMS: u16 = 0x50B;
pub const CMSG_SET_CHARACTER_MODEL: u16 = 0x50C;
pub const SMSG_CONNECT_TO: u16 = 0x50D;
pub const CMSG_CONNECT_TO_FAILED: u16 = 0x50E;
pub const SMSG_SUSPEND_COMMS: u16 = 0x50F;
pub const CMSG_SUSPEND_COMMS_ACK: u16 = 0x510;
pub const SMSG_RESUME_COMMS: u16 = 0x511;
pub const CMSG_AUTH_CONTINUED_SESSION: u16 = 0x512;
pub const CMSG_DROP_NEW_CONNECTION: u16 = 0x513;
pub const SMSG_SEND_ALL_COMBAT_LOG: u16 = 0x514;
pub const SMSG_OPEN_LFG_DUNGEON_FINDER: u16 = 0x515;
pub const SMSG_MOVE_SET_COLLISION_HGT: u16 = 0x516;
pub const CMSG_MOVE_SET_COLLISION_HGT_ACK: u16 = 0x517;
pub const MSG_MOVE_SET_COLLISION_HGT: u16 = 0x518;
pub const CMSG_CLEAR_RANDOM_BG_WIN_TIME: u16 = 0x519;
pub const CMSG_CLEAR_HOLIDAY_BG_WIN_TIME: u16 = 0x51A;
pub const CMSG_COMMENTATOR_SKIRMISH_QUEUE_COMMAND: u16 = 0x51B; // lua: CommentatorSetSkirmishMatchmakingMode/CommentatorRequestSkirmishQueueData/CommentatorRequestSkirmishMode/CommentatorStartSkirmishMatch
pub const SMSG_COMMENTATOR_SKIRMISH_QUEUE_RESULT1: u16 = 0x51C; // event EVENT_COMMENTATOR_SKIRMISH_QUEUE_REQUEST; CGCommentator::QueueNode
pub const SMSG_COMMENTATOR_SKIRMISH_QUEUE_RESULT2: u16 = 0x51D; // event EVENT_COMMENTATOR_SKIRMISH_QUEUE_REQUEST
pub const SMSG_COMPRESSED_UNKNOWN_1310: u16 = 0x51E; // some compressed packet
pub const NUM_MSG_TYPES: u16 = 0x51F;
