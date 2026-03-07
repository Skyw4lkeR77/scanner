"""Database migration script to add new columns for enhanced scanner."""
import os
import sys
from sqlalchemy import create_engine, text, inspect
from app.config import settings
from app.database import Base, engine


def migrate_database():
    """
    Migrate database to add new columns for:
    - Timezone-aware timestamps (Asia/Jakarta)
    - Xray integration fields
    - Detailed finding fields (endpoint, parameter, request/response)
    """
    print("Starting database migration...")
    
    # Get database connection
    db_url = settings.DATABASE_URL
    is_sqlite = db_url.startswith("sqlite")
    
    if is_sqlite:
        # For SQLite, we need to use raw connection
        conn = engine.connect()
    else:
        conn = engine.connect()
    
    inspector = inspect(engine)
    
    # ============================================================================
    # Migrate jobs table
    # ============================================================================
    print("\n[Migrating jobs table...]")
    
    jobs_columns = [col['name'] for col in inspector.get_columns('jobs')]
    
    new_job_columns = {
        'nuclei_output_file': 'VARCHAR(512)',
        'xray_output_file': 'VARCHAR(512)',
        'katana_output_file': 'VARCHAR(512)',
        'nuclei_findings_count': 'INTEGER DEFAULT 0',
        'xray_findings_count': 'INTEGER DEFAULT 0',
        'scan_duration_seconds': 'INTEGER',
        'endpoints_discovered': 'INTEGER DEFAULT 0',
        'xray_pid': 'INTEGER',
    }
    
    for col_name, col_type in new_job_columns.items():
        if col_name not in jobs_columns:
            try:
                if is_sqlite:
                    conn.execute(text(f"ALTER TABLE jobs ADD COLUMN {col_name} {col_type}"))
                else:
                    conn.execute(text(f"ALTER TABLE jobs ADD COLUMN IF NOT EXISTS {col_name} {col_type}"))
                conn.commit()
                print(f"  ✓ Added column: {col_name}")
            except Exception as e:
                print(f"  ⚠ Error adding {col_name}: {e}")
        else:
            print(f"  • Column already exists: {col_name}")
    
    # ============================================================================
    # Migrate findings table
    # ============================================================================
    print("\n[Migrating findings table...]")
    
    findings_columns = [col['name'] for col in inspector.get_columns('findings')]
    
    new_finding_columns = {
        'source': 'VARCHAR(50) DEFAULT "nuclei"',
        'endpoint_path': 'VARCHAR(2048)',
        'http_method': 'VARCHAR(10)',
        'vulnerable_parameter': 'VARCHAR(512)',
        'parameter_location': 'VARCHAR(50)',
        'request_data': 'TEXT',
        'response_data': 'TEXT',
        'references': 'TEXT',
        'cvss_score': 'FLOAT',
        'cvss_vector': 'VARCHAR(100)',
    }
    
    for col_name, col_type in new_finding_columns.items():
        if col_name not in findings_columns:
            try:
                if is_sqlite:
                    conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"))
                else:
                    conn.execute(text(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col_name} {col_type}"))
                conn.commit()
                print(f"  ✓ Added column: {col_name}")
            except Exception as e:
                print(f"  ⚠ Error adding {col_name}: {e}")
        else:
            print(f"  • Column already exists: {col_name}")
    
    # ============================================================================
    # Update existing findings to have source='nuclei' if null
    # ============================================================================
    print("\n[Updating existing data...]")
    
    try:
        result = conn.execute(text("UPDATE findings SET source = 'nuclei' WHERE source IS NULL OR source = ''"))
        conn.commit()
        print(f"  ✓ Updated {result.rowcount} findings with default source")
    except Exception as e:
        print(f"  ⚠ Error updating findings source: {e}")
    
    # ============================================================================
    # Create indexes for better performance
    # ============================================================================
    print("\n[Creating indexes...]")
    
    indexes_to_create = [
        ('idx_findings_source', 'findings', 'source'),
        ('idx_findings_endpoint', 'findings', 'endpoint_path'),
        ('idx_findings_parameter', 'findings', 'vulnerable_parameter'),
        ('idx_jobs_scan_mode', 'jobs', 'scan_mode'),
    ]
    
    for idx_name, table, column in indexes_to_create:
        try:
            conn.execute(text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({column})"))
            conn.commit()
            print(f"  ✓ Created index: {idx_name}")
        except Exception as e:
            print(f"  ⚠ Error creating index {idx_name}: {e}")
    
    conn.close()
    
    print("\n" + "=" * 60)
    print("Database migration completed!")
    print("=" * 60)
    print("\nNew features enabled:")
    print("  • Timezone support: Asia/Jakarta (WIB)")
    print("  • Xray scanner integration")
    print("  • Detailed endpoint and parameter tracking")
    print("  • Request/response data storage")
    print("  • CVSS scoring support")
    print("\nNote: Existing timestamps will remain in UTC.")
    print("      New timestamps will use Asia/Jakarta timezone.")


def rollback_migration():
    """
    Rollback migration (remove new columns).
    WARNING: This will delete data in these columns!
    """
    print("Rolling back migration...")
    print("WARNING: This will remove all new columns and their data!")
    
    response = input("Are you sure? (yes/no): ")
    if response.lower() != "yes":
        print("Rollback cancelled.")
        return
    
    conn = engine.connect()
    
    # Remove columns from findings
    columns_to_remove = [
        'source', 'endpoint_path', 'http_method', 'vulnerable_parameter',
        'parameter_location', 'request_data', 'response_data', 'references',
        'cvss_score', 'cvss_vector'
    ]
    
    for col in columns_to_remove:
        try:
            conn.execute(text(f"ALTER TABLE findings DROP COLUMN IF EXISTS {col}"))
            conn.commit()
            print(f"  ✓ Removed column: {col}")
        except Exception as e:
            print(f"  ⚠ Error removing {col}: {e}")
    
    # Remove columns from jobs
    job_columns_to_remove = [
        'nuclei_output_file', 'xray_output_file', 'katana_output_file',
        'nuclei_findings_count', 'xray_findings_count', 'scan_duration_seconds',
        'endpoints_discovered', 'xray_pid'
    ]
    
    for col in job_columns_to_remove:
        try:
            conn.execute(text(f"ALTER TABLE jobs DROP COLUMN IF EXISTS {col}"))
            conn.commit()
            print(f"  ✓ Removed column: {col}")
        except Exception as e:
            print(f"  ⚠ Error removing {col}: {e}")
    
    conn.close()
    print("\nRollback completed.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database migration tool")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration")
    
    args = parser.parse_args()
    
    if args.rollback:
        rollback_migration()
    else:
        migrate_database()
