'use strict';
// The mobile game reads one static field at both audited clamp sites. The
// lease is restricted to one eligible UpdateDead call and restored on exit.
globalThis.TMALRespawnClampLease = function(read,write,replacement) {
    if(replacement!==2147483647)throw Error('Unrecognized original clamp request');
    let active=null;
    function exit(token){
        if(active!==token||token===null)throw Error('Respawn clamp lease ownership differs');
        try {write(token.original);if(read()!==token.original)throw Error('Respawn clamp restoration failed');}
        finally {active=null;}
    }
    return {
        enter(){
            if(active!==null)throw Error('Overlapping respawn clamp calls');
            const original=read();if(original!==3600)throw Error('Respawn clamp baseline differs');
            const token={original};active=token;
            try {write(replacement);if(read()!==replacement)throw Error('Respawn clamp write failed');return token;}
            catch(error){exit(token);throw error;}
        },exit
    };
};
