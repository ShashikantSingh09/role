set -euo pipefail

ROLE="test-role"
DIR="readonly"

# Optional: AWS managed ReadOnlyAccess
# aws iam attach-role-policy --role-name "$ROLE" \
#   --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

create_and_attach () {
  local file="$1"
  local name="${file%.json}"


  if ! ARN=$(aws iam create-policy \
        --policy-name "$name" \
        --policy-document "file://$DIR/$file" \
        --query 'Policy.Arn' --output text 2>/tmp/err.txt); then

    if grep -q 'EntityAlreadyExists' /tmp/err.txt; then

      ARN=$(aws iam list-policies --scope Local --query \
        "Policies[?PolicyName=='$name'].Arn | [0]" --output text)
    else
      echo "Failed to create $name:"
      cat /tmp/err.txt
      exit 1
    fi
  fi

  if [ -z "$ARN" ] || [ "$ARN" = "None" ]; then
    echo "Could not resolve ARN for $name"; exit 1
  fi
  aws iam attach-role-policy --role-name "$ROLE" --policy-arn "$ARN"
  echo "Attached $name -> $ARN"
}

for f in ManagedReadOnly-*.json; do
  create_and_attach "$f"
done

DENY_NAME="DenySensitiveDataReads"
DENY_FILE="readonly/deny-sensitive-data-overlay.json"

if ! DENY_ARN=$(aws iam create-policy \
      --policy-name "$DENY_NAME" \
      --policy-document "file://$DENY_FILE" \
      --query 'Policy.Arn' --output text 2>/tmp/deny_err.txt); then
  if grep -q 'EntityAlreadyExists' /tmp/deny_err.txt; then
    DENY_ARN=$(aws iam list-policies --scope Local --query \
      "Policies[?PolicyName=='$DENY_NAME'].Arn | [0]" --output text)
  else
    echo "Failed to create $DENY_NAME:"; cat /tmp/deny_err.txt; exit 1
  fi
fi

[ -z "$DENY_ARN" -o "$DENY_ARN" = "None" ] && { echo "No ARN for deny policy"; exit 1; }
aws iam attach-role-policy --role-name "$ROLE" --policy-arn "$DENY_ARN"
echo "Attached $DENY_NAME -> $DENY_ARN"
