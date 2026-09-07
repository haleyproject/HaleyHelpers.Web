using static Haley.Internal.BrowserSessionFields;

namespace Haley.Internal;

internal static class BrowserSessionQueries
{
    internal const string Insert = $"""
        INSERT INTO `browser_session`
          (`scope`,`handle_hash`,`session_uid`,`subject_uid`,`payload`,`status`,`version`,`created_at`,`accessed_at`,`expires_at`)
        VALUES ({Scope},{HandleHash},{SessionUid},{SubjectUid},{Payload},'active',1,{CreatedAt},{CreatedAt},{ExpiresAt});
        """;

    internal const string Acquire = $"""
        UPDATE `browser_session`
           SET `lease_uid`={LeaseUid},`lease_exp`={LeaseExpiresAt},`accessed_at`={AccessedAt}
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `status`='active'
           AND `expires_at`>{AccessedAt}
           AND (`lease_uid` IS NULL OR `lease_exp`<={AccessedAt});
        """;

    internal const string FindLease = $"""
        SELECT `session_uid`,`subject_uid`,`payload`,`expires_at`,`version`
          FROM `browser_session`
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `lease_uid`={LeaseUid}
           AND `status`='active' LIMIT 1;
        """;

    internal const string Complete = $"""
        UPDATE `browser_session`
           SET `payload`={Payload},`expires_at`={ExpiresAt},`accessed_at`={AccessedAt},
               `version`=`version`+1,`lease_uid`=NULL,`lease_exp`=NULL
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `lease_uid`={LeaseUid}
           AND `version`={RecordVersion} AND `status`='active';
        """;

    internal const string Release = $"""
        UPDATE `browser_session` SET `lease_uid`=NULL,`lease_exp`=NULL
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `lease_uid`={LeaseUid};
        """;

    internal const string FindForRevoke = $"""
        SELECT `session_uid`,`subject_uid`
          FROM `browser_session`
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `status`='active' LIMIT 1;
        """;

    internal const string Revoke = $"""
        UPDATE `browser_session`
           SET `status`='revoked',`revoked_at`={RevokedAt},`lease_uid`=NULL,`lease_exp`=NULL
         WHERE `scope`={Scope} AND `handle_hash`={HandleHash} AND `status`='active';
        """;

    internal const string RemoveExpired = $"""
        DELETE FROM `browser_session`
         WHERE `scope`={Scope}
           AND ((`status`='active' AND `expires_at`<={RemoveBefore})
             OR (`status`='revoked' AND `revoked_at`<={RemoveBefore}));
        """;
}
