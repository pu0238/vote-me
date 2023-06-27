cargo fmt
dfx deploy vote_me_backend --argument '(variant { Regtest }, variant { Test })' --yes --upgrade-unchanged
npm run test