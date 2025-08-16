"""Neo4j database schema initialization."""

from neo4j import GraphDatabase, Session


class Neo4jDDL:
    """Manages Neo4j schema creation and indexes."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_constraints(self):
        """Create uniqueness constraints."""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AttackPattern) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:IntrusionSet) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tactic) REQUIRE n.shortname IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:DataSource) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AttackEpisode) REQUIRE n.episode_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AttackAction) REQUIRE n.action_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:D3fendTechnique) REQUIRE n.d3fend_id IS UNIQUE"
        ]
        
        for constraint in constraints:
            self.session.run(constraint)
    
    def create_indexes(self):
        """Create performance indexes."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (n:AttackPattern) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:AttackPattern) ON (n.x_mitre_is_subtechnique)",
            "CREATE INDEX IF NOT EXISTS FOR (n:IntrusionSet) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Mitigation) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Tactic) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:DataSource) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:AttackEpisode) ON (n.created)",
            "CREATE INDEX IF NOT EXISTS FOR (n:AttackAction) ON (n.timestamp)"
        ]
        
        for index in indexes:
            self.session.run(index)
    
    def create_fulltext_indexes(self):
        """Create full-text search indexes."""
        fulltext_indexes = [
            """
            CREATE FULLTEXT INDEX attack_pattern_search IF NOT EXISTS
            FOR (n:AttackPattern)
            ON EACH [n.name, n.description]
            """,
            """
            CREATE FULLTEXT INDEX intrusion_set_search IF NOT EXISTS
            FOR (n:IntrusionSet)
            ON EACH [n.name, n.description, n.aliases]
            """,
            """
            CREATE FULLTEXT INDEX software_search IF NOT EXISTS
            FOR (n:Software)
            ON EACH [n.name, n.description]
            """
        ]
        
        for index in fulltext_indexes:
            self.session.run(index)
    
    def initialize_schema(self):
        """Initialize the complete schema."""
        self.create_constraints()
        self.create_indexes()
        self.create_fulltext_indexes()
        print("Neo4j schema initialized successfully")


def ensure_ddl(uri: str, user: str, password: str):
    """Ensure Neo4j DDL is initialized."""
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        ddl = Neo4jDDL(session)
        ddl.initialize_schema()
    driver.close()