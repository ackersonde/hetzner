#!/bin/sh

# this should only be run in a uninitialized, new instance of vault
# (e.g. volume doesn't have vault config/data in it)
chown vault:vault /vault/
vault operator init -key-shares=3 -key-threshold=2 > generated_keys.txt

keyArray=$(grep 'Unseal Key ' < generated_keys.txt  | cut -c15-)
for s in $keyArray; do
  vault operator unseal "$s"
done
unset keyArray
export VAULT_TOKEN=$(grep "Initial Root Token: " < generated_keys.txt  | cut -c21-)

# Enable kv
vault secrets enable -version=2 kv

# Enable userpass and add default user
# vault auth enable userpass
# vault policy write spring-policy spring-policy.hcl
# vault write auth/userpass/users/admin password=${SECRET_PASS} policies=spring-policy

# Add test value to my-secret
#vault kv put kv/my-secret my-value=s3cr3t
