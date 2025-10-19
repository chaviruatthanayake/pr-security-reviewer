#!/bin/bash

# This script creates all the source files for the project

echo "Creating source files..."

# Create src/db.ts
cat > src/db.ts << 'EOF'
import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient({
  log: ['error', 'warn'],
});
EOF

echo "✓ Created src/db.ts"

# Since this is getting very long, let me provide you a better way...
