"""
BiblicalScholarAgent - Religious Studies & Biblical Scholarship
===============================================================

Provides religious text analysis, quote identification, comparative religion studies,
theological research, and scriptural interpretation across multiple faith traditions.
"""

import logging
import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)


class Religion(Enum):
    """Major world religions."""
    CHRISTIANITY = "christianity"
    ISLAM = "islam"
    JUDAISM = "judaism"
    HINDUISM = "hinduism"
    BUDDHISM = "buddhism"
    SIKHISM = "sikhism"
    BAHAI = "bahai"
    JAINISM = "jainism"
    SHINTO = "shinto"
    TAOISM = "taoism"
    CONFUCIANISM = "confucianism"
    ZOROASTRIANISM = "zoroastrianism"
    INDIGENOUS = "indigenous"
    NEW_AGE = "new_age"
    SECULAR = "secular"


class ScriptureType(Enum):
    """Types of religious texts."""
    SCRIPTURE = "scripture"
    GOSPEL = "gospel"
    EPISTLE = "epistle"
    PROPHECY = "prophecy"
    PSALM = "psalm"
    HADITH = "hadith"
    SUTRA = "sutra"
    VEDA = "veda"
    UPANISHAD = "upanishad"
    TORAH = "torah"
    TALMUD = "talmud"
    QURAN = "quran"
    BHAKTI = "bhakti"
    DHARMA = "dharma"
    KOAN = "koan"


@dataclass
class ReligiousText:
    """Religious text or scripture."""
    text_id: str
    title: str
    religion: Religion
    scripture_type: ScriptureType
    book_name: str = ""
    chapter: Optional[int] = None
    verse: Optional[int] = None
    verse_range: Optional[str] = None
    content: str = ""
    language_original: str = ""
    translation_used: str = ""
    author_attributed: str = ""
    date_written: Optional[str] = None
    context: str = ""
    themes: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)


@dataclass
class QuoteAnalysis:
    """Analysis of a religious quote or passage."""
    quote_id: str
    quote_text: str
    source_text: ReligiousText
    translation_variants: List[str] = field(default_factory=list)
    literal_translation: str = ""
    idiomatic_meaning: str = ""
    theological_significance: str = ""
    historical_context: str = ""
    common_misinterpretations: List[str] = field(default_factory=list)
    related_quotes: List[str] = field(default_factory=list)
    cross_references: List[str] = field(default_factory=list)
    scholarly_interpretations: List[Dict[str, str]] = field(default_factory=list)
    application_examples: List[str] = field(default_factory=list)


@dataclass
class ComparativeStudy:
    """Comparative study across religions."""
    study_id: str
    topic: str
    religions_compared: List[Religion] = field(default_factory=list)
    similarities: List[str] = field(default_factory=list)
    differences: List[str] = field(default_factory=list)
    unique_concepts: Dict[str, List[str]] = field(default_factory=dict)
    shared_values: List[str] = field(default_factory=list)
    divergent_practices: List[str] = field(default_factory=list)
    theological_insights: List[str] = field(default_factory=list)
    practical_implications: List[str] = field(default_factory=list)


@dataclass
class ResearchQuery:
    """Research query for biblical/theological study."""
    query_id: str
    question: str
    religion_focus: Optional[Religion] = None
    scripture_focus: Optional[ScriptureType] = None
    date_range: Optional[Tuple[str, str]] = None
    keywords: List[str] = field(default_factory=list)
    sources_consulted: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    confidence_level: str = "medium"  # low, medium, high
    sources: List[Dict[str, str]] = field(default_factory=list)


class BiblicalScholarAgent:
    """
    Biblical Scholar Agent for religious text analysis,
    comparative religion studies, and theological research.
    """

    def __init__(self, agent_id: str = "biblical-scholar-agent"):
        self.agent_id = agent_id
        self.texts: Dict[str, ReligiousText] = {}
        self.quote_analyses: Dict[str, QuoteAnalysis] = {}
        self.comparative_studies: Dict[str, ComparativeStudy] = {}
        self.research_queries: Dict[str, ResearchQuery] = {}
        self.quote_database: Dict[str, str] = {}  # quote -> source
        self.religious_concepts: Dict[str, Set[str]] = {}  # concept -> religions
        self.themes_index: Dict[str, List[str]] = {}  # theme -> text IDs

        # Initialize with core religious texts
        self._init_core_texts()
        self._init_quote_database()
        self._init_concept_index()

    def _init_core_texts(self):
        """Initialize core religious texts database."""
        # This would normally load from a database or external source
        # For now, we'll have a representative sample
        
        # Christian texts
        self.texts["john_3_16"] = ReligiousText(
            text_id="john_3_16",
            title="John 3:16",
            religion=Religion.CHRISTIANITY,
            scripture_type=ScriptureType.GOSPEL,
            book_name="John",
            chapter=3,
            verse=16,
            content="For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.",
            language_original="Greek",
            translation_used="NIV",
            author_attributed="John the Apostle",
            date_written="c. 90-110 AD",
            context="Part of Jesus' conversation with Nicodemus about salvation",
            themes=["love", "salvation", "faith", "eternal life"],
            keywords=["god", "love", "world", "son", "believe", "eternal life"]
        )
        
        self.texts["genesis_1_1"] = ReligiousText(
            text_id="genesis_1_1",
            title="Genesis 1:1",
            religion=Religion.JUDAISM,
            scripture_type=ScriptureType.TORAH,
            book_name="Genesis",
            chapter=1,
            verse=1,
            content="In the beginning God created the heavens and the earth.",
            language_original="Hebrew",
            translation_used="NIV",
            author_attributed="Moses (traditional)",
            date_written="c. 1400-1200 BC",
            context="Opening verse of the Bible, creation narrative",
            themes=["creation", "god", "beginnings", "sovereignty"],
            keywords=["beginning", "god", "created", "heavens", "earth"]
        )
        
        # Islamic texts
        self.texts["quran_fatiha"] = ReligiousText(
            text_id="quran_fatiha",
            title="Al-Fatihah (The Opening)",
            religion=Religion.ISLAM,
            scripture_type=ScriptureType.QURAN,
            book_name="Al-Fatihah",
            chapter=1,
            verse_range="1-7",
            content="In the name of Allah, the Most Gracious, the Most Merciful. Praise be to Allah, Lord of all worlds. The Most Gracious, the Most Merciful. Master of the Day of Judgment. You alone we worship, and You alone we ask for help. Guide us to the straight path, the path of those who have received Your grace; not the path of those who have evoked [Your] anger or of those who are astray.",
            language_original="Arabic",
            translation_used="Sahih International",
            author_attributed="Allah (revealed to Muhammad)",
            date_written="c. 610-632 AD",
            context="Opening chapter of the Quran, recited in daily prayers",
            themes=["praise", "mercy", "guidance", "worship", "judgment"],
            keywords=["allah", "merciful", "praise", "worlds", "judgment", "worship", "guide"]
        )
        
        # Hindu texts
        self.texts["bhagavad_gita_2_47"] = ReligiousText(
            text_id="bhagavad_gita_2_47",
            title="Bhagavad Gita 2:47",
            religion=Religion.HINDUISM,
            scripture_type=ScriptureType.SUTRAS,
            book_name="Bhagavad Gita",
            chapter=2,
            verse=47,
            content="You have the right to work only but never to the fruits of work. You should never engage in action for the sake of reward, nor should you long for inaction.",
            language_original="Sanskrit",
            translation_used="Swami Sivananda",
            author_attributed="Vyasa (traditional)",
            date_written="c. 400-200 BC",
            context="Krishna's teaching to Arjuna on detached action",
            themes=["duty", "detachment", "action", "karma", "selfless service"],
            keywords=["work", "fruits", "action", "reward", "inaction", "duty"]
        )
        
        # Buddhist texts
        self.texts["dhammapada_1"] = ReligiousText(
            text_id="dhammapada_1",
            title="Dhammapada 1:1",
            religion=Religion.BUDDHISM,
            scripture_type=ScriptureType.SUTRAS,
            book_name="Dhammapada",
            chapter=1,
            verse=1,
            content="Mind precedes all mental states. Mind is their chief; they are all mind-wrought. If with an impure mind a person speaks or acts suffering follows him like the wheel that follows the foot of the ox.",
            language_original="Pali",
            translation_used="Thanissaro Bhikkhu",
            author_attributed="Buddha",
            date_written="c. 3rd century BC",
            content="Mind precedes all mental states. Mind is their chief; they are all mind-wrought. If with an impure mind a person speaks or acts suffering follows him like the wheel that follows the foot of the ox.",
            themes=["mindfulness", "karma", "cause and effect", "mental purity"],
            keywords=["mind", "mental states", "speaks", "acts", "suffering", "follows"]
        )

    def _init_quote_database(self):
        """Initialize database of famous religious quotes for quick lookup."""
        self.quote_database = {
            "for god so loved the world": "john_3_16",
            "in the beginning god created": "genesis_1_1",
            "in the name of allah": "quran_fatiha",
            "you have the right to work": "bhagavad_gita_2_47",
            "mind precedes all mental states": "dhammapada_1",
            "love your neighbor as yourself": "leviticus_19_18",
            "the lord is my shepherd": "psalm_23_1",
            "i am the way the truth and the life": "john_14_6",
            "peace be upon you": "islamic_greeting",
            "om shanti shanti shanti": "hindu_peace_chant",
            "the kingdom of god is within you": "luke_17_21",
            "do unto others as you would have them do unto you": "matthew_7_12",
            "blessed are the poor in spirit": "matthew_5_3",
            "allah is sufficient for us": "quran_9_51",
            "all is vanity": "ecclesiastes_1_2",
            "the journey of a thousand miles begins with one step": "tao_te_ching_64",
            "know thyself": "delphic_maxim",
            "an unexamined life is not worth living": "socrates_apology",
        }
        
        # Add more texts for the quotes above
        self.texts["leviticus_19_18"] = ReligiousText(
            text_id="leviticus_19_18",
            title="Leviticus 19:18",
            religion=Religion.JUDAISM,
            scripture_type=Scripturetype.TORAH,
            book_name="Leviticus",
            chapter=19,
            verse=18,
            content="Do not seek revenge or bear a grudge against anyone among your people, but love your neighbor as yourself. I am the LORD.",
            language_original="Hebrew",
            translation_used="NIV",
            author_attributed="Moses",
            date_written="c. 1400-1200 BC",
            context="Part of the Holiness Code",
            themes=["love", "forgiveness", "neighbor", "holiness"],
            keywords=["love", "neighbor", "revenge", "grudge", "lord"]
        )
        
        self.texts["psalm_23_1"] = ReligiousText(
            text_id="psalm_23_1",
            title="Psalm 23:1",
            religion=Religion.JUDAISM,
            scripture_type=ScriptureType.PSALM,
            book_name="Psalms",
            chapter=23,
            verse=1,
            content="The LORD is my shepherd, I lack nothing.",
            language_original="Hebrew",
            translation_used="NIV",
            author_attributed="David",
            date_written="c. 1000 BC",
            context="A psalm of David about God's provision and protection",
            themes=["trust", "provision", "protection", "guidance"],
            keywords=["lord", "shepherd", "lack", "nothing"]
        )
        
        self.texts["john_14_6"] = ReligiousText(
            text_id="john_14_6",
            title="John 14:6",
            religion=Religion.CHRISTIANITY,
            scripture_type=ScriptureType.GOSPEL,
            book_name="John",
            chapter=14,
            verse=6,
            content="Jesus answered, 'I am the way and the truth and the life. No one comes to the Father except through me.'",
            language_original="Greek",
            translation_used="NIV",
            author_attributed="John the Apostle",
            date_written="c. 90-110 AD",
            context="Jesus speaking to his disciples about the Father",
            themes=["jesus", "way", "truth", "life", "father", "exclusivity"],
            keywords=["jesus", "way", "truth", "life", "father", "except", "through", "me"]
        )
        
        self.texts["matthew_7_12"] = ReligiousText(
            text_id="matthew_7_12",
            title="Matthew 7:12",
            religion=Religion.CHRISTIANITY,
            scripture_type=ScriptureType.GOSPEL,
            book_name="Matthew",
            chapter=7,
            verse=12,
            content="So in everything, do to others what you would have them do to you, for this sums up the Law and the Prophets.",
            language_original="Greek",
            translation_used="NIV",
            author_attributed="Matthew",
            date_written="c. 70-80 AD",
            context="Part of the Sermon on the Mount",
            themes=["golden rule", "ethics", "reciprocity", "law", "prophets"],
            keywords=["do", "others", "would", "have", "them", "do", "you", "sums", "up", "law", "prophets"]
        )
        
        self.texts["matthew_5_3"] = ReligiousText(
            text_id="matthew_5_3",
            title="Matthew 5:3",
            religion=Religion.CHRISTIANITY,
            scripture_type=ScriptureType.GOSPEL,
            book_name="Matthew",
            chapter=5,
            verse=3,
            content="Blessed are the poor in spirit, for theirs is the kingdom of heaven.",
            language_original="Greek",
            translation_used="NIV",
            author_attributed="Matthew",
            date_written="c. 70-80 AD",
            context="First Beatitude in the Sermon on the Mount",
            themes=["blessed", "poor", "spirit", "kingdom", "heaven"],
            keywords=["blessed", "poor", "in", "spirit", "theirs", "kingdom", "heaven"]
        )
        
        self.texts["ecclesiastes_1_2"] = ReligiousText(
            text_id="ecclesiastes_1_2",
            title="Ecclesiastes 1:2",
            religion=Religion.JUDAISM,
            scripture_type=ScriptureType.WISDOM,
            book_name="Ecclesiastes",
            chapter=1,
            verse=2,
            content='"Meaningless! Meaningless!" says the Teacher. "Utterly meaningless! Everything is meaningless."',
            language_original="Hebrew",
            translation_used="NIV",
            author_attributed="King Solomon",
            date_written="c. 935 BC",
            context="Opening of Ecclesiastes, reflecting on life's meaning",
            themes=["meaningless", "vanity", "teacher", "everything"],
            keywords=["meaningless", "utterly", "everything"]
        )
        
        self.texts["tao_te_ching_64"] = ReligiousText(
            text_id="tao_te_ching_64",
            title="Tao Te Ching Chapter 64",
            religion=Religion.TAOISM,
            scripture_type=ScriptureType.SUTRAS,
            book_name="Tao Te Ching",
            chapter=64,
            content="A journey of a thousand miles begins with a single step.",
            language_original="Chinese",
            translation_used="Stephen Mitchell",
            author_attributed="Laozi",
            date_written="c. 4th century BC",
            context="Teaching about beginnings and perseverance",
            themes=["journey", "beginning", "step", "perseverance"],
            keywords=["journey", "thousand", "miles", "begins", "single", "step"]
        )

    def _init_concept_index(self):
        """Initialize index of religious concepts across traditions."""
        self.religious_concepts = {
            "god": {Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM, Religion.HINDUISM},
            "creation": {Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM},
            "prophecy": {Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM},
            "law": {Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM},
            "afterlife": {Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM, Religion.HINDUISM, Religion.BUDDHISM},
            "salvation": {Religion.CHRISTIANITY, Religion.ISLAM},
            "enlightenment": {Religion.BUDDHISM, Religion.HINDUISM},
            "karma": {Religion.HINDUISM, Religion.BUDDHISM, Religion.JAINISM},
            "dharma": {Religion.HINDUISM, Religion.BUDDHISM, Religion.JAINISM, Religion.SIKHISM},
            "tao": {Religion.TAOISM},
            "logos": {Religion.CHRISTIANITY, Religion.PHILOSOPHY},
        }

    # ============================================
    # Text Management
    # ============================================

    def add_text(
        self,
        title: str,
        religion: Religion,
        scripture_type: ScriptureType,
        content: str,
        book_name: str = "",
        chapter: Optional[int] = None,
        verse: Optional[int] = None,
        verse_range: Optional[str] = None,
        language_original: str = "",
        translation_used: str = "",
        author_attributed: str = "",
        date_written: Optional[str] = None,
        context: str = "",
    ) -> ReligiousText:
        """Add a religious text to the database."""
        text = ReligiousText(
            text_id=self._generate_id("text"),
            title=title,
            religion=religion,
            scripture_type=scripture_type,
            book_name=book_name,
            chapter=chapter,
            verse=verse,
            verse_range=verse_range,
            content=content,
            language_original=language_original,
            translation_used=translation_used,
            author_attributed=author_attributed,
            date_written=date_written,
            context=context,
        )

        # Extract themes and keywords (simplified)
        text.themes = self._extract_themes(content)
        text.keywords = self._extract_keywords(content)

        self.texts[text.text_id] = text
        self._index_text(text)

        logger.info(f"Added religious text: {text.title}")
        return text

    def get_text(self, text_id: str) -> Optional[ReligiousText]:
        """Get text by ID."""
        return self.texts.get(text_id)

    def get_texts_by_religion(self, religion: Religion) -> List[ReligiousText]:
        """Get all texts for a specific religion."""
        return [text for text in self.texts.values() if text.religion == religion]

    def get_texts_by_type(self, scripture_type: ScriptureType) -> List[ReligiousText]:
        """Get all texts of a specific type."""
        return [text for text in self.texts.values() if text.scripture_type == scripture_type]

    def search_texts(self, query: str) -> List[ReligiousText]:
        """Search texts by content, title, or keywords."""
        query_lower = query.lower()
        results = []

        for text in self.texts.values():
            searchable = (
                text.title.lower() +
                " " + text.content.lower() +
                " " + " ".join(text.keywords).lower() +
                " " + " ".join(text.themes).lower()
            )

            if query_lower in searchable:
                results.append(text)

        # Sort by relevance (simple keyword match count)
        results.sort(key=lambda t: sum(
            1 for word in query_lower.split() 
            if word in t.title.lower() or 
               word in t.content.lower() or 
               any(word in k.lower() for k in t.keywords)
        ), reverse=True)

        return results

    def get_random_text(self, religion: Optional[Religion] = None) -> Optional[ReligiousText]:
        """Get a random religious text."""
        import random
        
        texts = list(self.texts.values())
        if religion:
            texts = [t for t in texts if t.religion == religion]
        
        if not texts:
            return None
            
        return random.choice(texts)

    # ============================================
    # Quote Analysis
    # ============================================

    def analyze_quote(self, quote_text: str) -> QuoteAnalysis:
        """Analyze a religious quote for meaning, source, and significance."""
        quote_lower = quote_text.lower().strip()
        
        # Check if we know this quote
        source_id = None
        for known_quote, text_id in self.quote_database.items():
            if known_quote in quote_lower or quote_lower in known_quote:
                source_id = text_id
                break
        
        # If not found in database, try to search
        if not source_id:
            matching_texts = self.search_texts(quote_text)
            if matching_texts:
                source_id = matching_texts[0].text_id
        
        source_text = self.get_text(source_id) if source_id else None
        
        # Create analysis
        analysis = QuoteAnalysis(
            quote_id=self._generate_id("quote"),
            quote_text=quote_text,
            source_text=source_text or ReligiousText(
                text_id="unknown",
                title="Unknown Source",
                religion=Religion.SECULAR,
                scripture_type=ScriptureType.SCRIPTURE,
                content="Source not identified in database",
            ),
            literal_translation=self._get_literal_translation(quote_text, source_text) if source_text else "",
            idiomatic_meaning=self._get_idiomatic_meaning(quote_text, source_text) if source_text else "",
            theological_significance=self._get_theological_significance(quote_text, source_text) if source_text else "",
            historical_context=self._get_historical_context(source_text) if source_text else "",
            common_misinterpretations=self._get_common_misinterpretations(quote_text, source_text) if source_text else [],
            related_quotes=self._find_related_quotes(quote_text, source_text) if source_text else [],
            cross_references=self._find_cross_references(quote_text, source_text) if source_text else [],
            scholarly_interpretations=self._get_scholarly_interpretations(quote_text, source_text) if source_text else [],
            application_examples=self._get_application_examples(quote_text, source_text) if source_text else [],
        )
        
        # Add translation variants if applicable
        if source_text and source_text.translation_used:
            analysis.translation_variants = self._get_translation_variants(source_text)
        
        self.quote_analyses[analysis.quote_id] = analysis
        
        logger.info(f"Analyzed quote: {quote_text[:50]}...")
        return analysis

    def get_quote_analysis(self, quote_id: str) -> Optional[QuoteAnalysis]:
        """Get quote analysis by ID."""
        return self.quote_analyses.get(quote_id)

    # ============================================
    # Comparative Studies
    # ============================================

    def compare_concept(
        self,
        concept: str,
        religions: Optional[List[Religion]] = None
    ) -> ComparativeStudy:
        """Compare how a concept is understood across religions."""
        if religions is None:
            # Default to major religions
            religions = [
                Religion.CHRISTIANITY, Religion.ISLAM, Religion.JUDAISM,
                Religion.HINDUISM, Religion.BUDDHISM
            ]
        
        study = ComparativeStudy(
            study_id=self._generate_id("study"),
            topic=concept,
            religions_compared=religions,
        )
        
        # Get similarities and differences (simplified)
        study.similarities, study.differences = self._analyze_concept_similarities_differences(
            concept, religions
        )
        
        # Get unique concepts per religion
        study.unique_concepts = self._get_unique_concepts(concept, religions)
        
        # Get shared values
        study.shared_values = self._get_shared_values(religions)
        
        # Get divergent practices
        study.divergent_practices = self._get_divergent_practices(religions)
        
        # Generate theological insights
        study.theological_insights = self._generate_theological_insights(concept, religions)
        
        # Generate practical implications
        study.practical_implications = self._generate_practical_implications(concept, religions)
        
        self.comparative_studies[study.study_id] = study
        
        logger.info(f"Created comparative study on: {concept}")
        return study

    def get_comparative_study(self, study_id: str) -> Optional[ComparativeStudy]:
        """Get comparative study by ID."""
        return self.comparative_studies.get(study_id)

    # ============================================
    # Research
    # ============================================

    def research_question(
        self,
        question: str,
        religion_focus: Optional[Religion] = None,
        scripture_focus: Optional[ScriptureType] = None,
        keywords: Optional[List[str]] = None,
    ) -> ResearchQuery:
        """Research a theological or biblical question."""
        query = ResearchQuery(
            query_id=self._generate_id("research"),
            question=question,
            religion_focus=religion_focus,
            scripture_focus=scripture_focus,
            keywords=keywords or [],
        )
        
        # Simulate research process
        query.sources_consulted = self._conduct_literature_search(question, religion_focus, scripture_focus)
        query.findings = self._analyze_findings(question, query.sources_consulted)
        query.confidence_level = self._assess_confidence(query.findings)
        query.sources = self._format_sources(query.sources_consulted)
        
        self.research_queries[query.query_id] = query
        
        logger.info(f"Researched question: {question}")
        return query

    def get_research(self, query_id: str) -> Optional[ResearchQuery]:
        """Get research query by ID."""
        return self.research_queries.get(query_id)

    # ============================================
    # Utilities
    # ============================================

    def _extract_themes(self, text: str) -> List[str]:
        """Extract themes from text (simplified)."""
        theme_indicators = {
            "love": ["love", "compassion", "charity", "kindness"],
            "faith": ["faith", "belief", "trust", "devotion"],
            "hope": ["hope", "expectation", "aspiration"],
            "peace": ["peace", "tranquility", "harmony", "calm"],
            "justice": ["justice", "fairness", "equity", "righteousness"],
            "mercy": ["mercy", "forgiveness", "compassion", "leniency"],
            "wisdom": ["wisdom", "knowledge", "understanding", "insight"],
            "courage": ["courage", "bravery", "strength", "fortitude"],
            "humility": ["humility", "meekness", "modesty", "humbleness"],
            "gratitude": ["gratitude", "thankfulness", "appreciation", "thanks"],
            "service": ["service", "ministry", "helping", "giving"],
            "sacrifice": ["sacrifice", "offering", "giving up", "selfless"],
            "prayer": ["prayer", "supplication", "invocation", "worship"],
            "meditation": ["meditation", "contemplation", "reflection", "mindfulness"],
            "fasting": ["fasting", "abstinence", "self-denial", "sacrifice"],
            "pilgrimage": ["pilgrimage", "journey", "sacred travel", "holy site"],
        }
        
        themes = []
        text_lower = text.lower()
        
        for theme, keywords in theme_indicators.items():
            if any(keyword in text_lower for keyword in keywords):
                themes.append(theme)
        
        return themes

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text (simplified)."""
        # Remove common words and extract meaningful terms
        stop_words = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", 
            "of", "with", "by", "is", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "will", "would", "should",
            "could", "may", "might", "must", "shall", "can", "this", "that", "these",
            "those", "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
            "us", "them", "my", "your", "his", "her", "its", "our", "their", "mine",
            "yours", "his", "hers", "ours", "theirs"
        }
        
        # Simple word extraction
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        # Return top keywords by frequency
        from collections import Counter
        word_counts = Counter(keywords)
        return [word for word, count in word_counts.most_common(20)]

    def _generate_id(self, prefix: str) -> str:
        """Generate a unique ID."""
        import secrets
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = secrets.token_hex(4)
        return f"{prefix}-{timestamp}-{random_suffix}"

    def _index_text(self, text: ReligiousText):
        """Index text for faster searching."""
        # Index by themes
        for theme in text.themes:
            if theme not in self.themes_index:
                self.themes_index[theme] = []
            self.themes_index[theme].append(text.text_id)
        
        # Index by concepts (simplified)
        for concept in self.religious_concepts:
            # Check if concept appears in text
            if concept.lower() in text.content.lower() or \
               any(concept.lower() in theme for theme in text.themes):
                if concept not in self.religious_concepts:
                    self.religious_concepts[concept] = set()
                self.religious_concepts[concept].add(text.religion)

    def _get_literal_translation(self, quote: str, source: ReligiousText) -> str:
        """Get literal translation of quote."""
        # Simplified - in reality would use linguistic databases
        if source.language_original == "Hebrew":
            return f"[Hebrew: literal translation of '{quote}']"
        elif source.language_original == "Greek":
            return f"[Greek: literal translation of '{quote}']"
        elif source.language_original == "Arabic":
            return f"[Arabic: literal translation of '{quote}']"
        elif source.language_original == "Sanskrit":
            return f"[Sanskrit: literal translation of '{quote}']"
        elif source.language_original == "Pali":
            return f"[Pali: literal translation of '{quote}']"
        elif source.language_original == "Chinese":
            return f"[Chinese: literal translation of '{quote}']"
        else:
            return quote  # Assume already in target language

    def _get_idiomatic_meaning(self, quote: str, source: ReligiousText) -> str:
        """Get idiomatic/functional meaning of quote."""
        # Simplified interpretation
        if "love" in quote.lower():
            return "Expresses deep affection, care, and commitment"
        elif "faith" in quote.lower():
            return "Refers to trust and confidence in divine promises"
        elif "peace" in quote.lower():
            return "Describes state of tranquility and harmony"
        elif "justice" in quote.lower():
            return "Relates to fairness, righteousness, and divine order"
        elif "mercy" in quote.lower():
            return "Indicates compassion and forgiveness toward others"
        elif "wisdom" in quote.lower():
            return "Pertains to practical understanding and discernment"
        else:
            return f"Teaches about {', '.join(source.themes[:2]) if source.themes else 'spiritual principles'}"

    def _get_theological_significance(self, quote: str, source: ReligiousText) -> str:
        """Get theological significance of quote."""
        significance_map = {
            Religion.CHRISTIANITY: "Central to Christian doctrine of salvation and God's love",
            Religion.ISLAM: "Fundamental to Islamic theology of Allah's attributes",
            Religion.JUDAISM: "Key to Jewish understanding of God's relationship with Israel",
            Religion.HINDUISM: "Important for Hindu concepts of dharma and spiritual liberation",
            Religion.BUDDHISM: "Essential to Buddhist teachings on mind and karma",
        }
        
        return significance_map.get(source.religion, "Contributes to religious understanding")

    def _get_historical_context(self, source: ReligiousText) -> str:
        """Get historical context of source text."""
        if not source.date_written:
            return "Historical period uncertain"
            
        return f"Written circa {source.date_written} in the context of {source.context}"

    def _get_common_misinterpretations(self, quote: str, source: ReligiousText) -> List[str]:
        """Get common misinterpretations of quote."""
        misinterpretations = {
            "john_3_16": [
                "God's love is unconditional and requires no response",
                "Belief means mere intellectual assent without transformation",
                "Eternal life begins only after physical death"
            ],
            "genesis_1_1": [
                "Creation happened in literal 24-hour days",
                "Science and creation accounts are necessarily contradictory",
                "God needed to rest because he was tired"
            ],
            "matthew_7_12": [
                "The Golden Rule is unique to Christianity",
                "This verse replaces all Old Testament law",
                "It means we should do whatever others want"
            ]
        }
        
        return misinterpretations.get(source.text_id, [
            "Taking the quote out of its literary and historical context",
            "Applying modern cultural assumptions to ancient text",
            "Ignoring the original audience and purpose"
        ])

    def _find_related_quotes(self, quote: str, source: ReligiousText) -> List[str]:
        """Find related quotes from same text or tradition."""
        related = []
        
        # Get other texts from same religion
        same_religion_texts = self.get_texts_by_religion(source.religion)
        
        # Look for thematic similarities
        for text in same_religion_texts[:5]:  # Limit to avoid too many
            if text.text_id != source.text_id:
                # Simple theme matching
                common_themes = set(source.themes) & set(text.themes)
                if len(common_themes) >= 2:
                    related.append(f"{text.title}: {text.content[:100]}...")
        
        return related[:3]  # Return top 3

    def _find_cross_references(self, quote: str, source: ReligiousText) -> List[str]:
        """Find cross-references to other religious texts."""
        # Simplified - would normally use concordance databases
        cross_refs = []
        
        if source.religion == Religion.CHRISTIANITY:
            # Look for OT quotes in NT or vice versa
            if "love your neighbor" in quote.lower():
                cross_refs.append("Leviticus 19:18 - Original command")
                cross_refs.append("Galatians 5:14 - Paul's summary")
            elif "lord is my shepherd" in quote.lower():
                cross_refs.append("John 10:11 - Jesus as Good Shepherd")
                cross_refs.append("Ezekiel 34:11-16 - God as Shepherd")
        
        return cross_refs

    def _get_scholarly_interpretations(self, quote: str, source: ReligiousText) -> List[Dict[str, str]]:
        """Get scholarly interpretations of quote."""
        # Simplified - would normally query theological databases
        interpretations = []
        
        if source.religion == Religion.CHRISTIANITY:
            interpretations.append({
                "scholar": "N.T. Wright",
                "perspective": "New Perspective on Paul",
                "interpretation": "Emphasizes corporate and covenantal aspects"
            })
            interpretations.append({
                "scholar": "John Piper",
                "perspective": "Reformed Evangelical",
                "interpretation": "Focuses on God's glory and sovereign grace"
            })
        elif source.religion == Religion.ISLAM:
            interpretations.append({
                "scholar": "Seyyed Hossein Nasr",
                "perspective": "Traditionalist",
                "interpretation": "Emphasizes metaphysical and spiritual dimensions"
            })
        
        return interpretations

    def _get_application_examples(self, quote: str, source: ReligiousText) -> List[str]:
        """Get practical application examples."""
        examples = {
            "john_3_16": [
                "Sharing the gospel message with others",
                "Trusting in God's love during difficult times",
                "Motivation for Christian missions and evangelism"
            ],
            "matthew_7_12": [
                "Treating coworkers with respect and fairness",
                "Considering how your actions affect others before acting",
                "Practicing empathy in conflicts and disagreements"
            ],
            "love your neighbor as yourself": [
                "Volunteering at a local shelter or food bank",
                "Listening attentively to someone with different views",
                "Forgiving someone who has hurt you"
            ]
        }
        
        # Find matching key
        for key, value in examples.items():
            if key in quote.lower():
                return value
        
        # Default examples based on themes
        if "love" in source.themes:
            return ["Showing compassion to those in need", "Practicing forgiveness in relationships"]
        elif "faith" in source.themes:
            return ["Trusting God during uncertainty", "Sharing your beliefs respectfully"]
        elif "peace" in source.themes:
            return ["Seeking reconciliation in conflicts", "Creating peaceful environments"]
        else:
            return ["Applying the principle to daily life", "Reflecting on its meaning regularly"]

    def _get_translation_variants(self, source: ReligiousText) -> List[str]:
        """Get common translation variants."""
        variants = {
            "john_3_16": [
                "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. (KJV)",
                "For God loved the world in this way: He gave his one and only Son, so that everyone who believes in him will not perish but have eternal life. (CSB)"
            ],
            "genesis_1_1": [
                "In the beginning God created the heaven and the earth. (KJV)",
                "In the beginning when God created the heavens and the earth. (NRSV)"
            ],
            "matthew_7_12": [
                "Therefore all things whatsoever ye would that men should do to you, do ye even so to them: for this is the law and the prophets. (KJV)",
                "In everything, therefore, treat people the same way you want them to treat you, for this is the Law and the Prophets. (NRSV)"
            ]
        }
        
        return variants.get(source.text_id, [])

    def _analyze_concept_similarities_differences(
        self,
        concept: str,
        religions: List[Religion]
    ) -> Tuple[List[str], List[str]]:
        """Analyze similarities and differences in concept understanding."""
        similarities = []
        differences = []
        
        # Simplified analysis
        if concept.lower() == "god":
            similarities = [
                "Belief in a supreme divine reality",
                "Divine reality is ultimate source of existence",
                "Divine reality is worthy of worship and reverence"
            ]
            differences = [
                "Christianity: Trinitarian understanding (Father, Son, Holy Spirit)",
                "Islam: Strict monotheism (Tawhid), rejects Trinity",
                "Judaism: Monotheistic, emphasis on covenant relationship",
                "Hinduism: Both monistic and theistic traditions, many deities as manifestations",
                "Buddhism: Generally non-theistic, focuses on enlightenment rather than deity"
            ]
        elif concept.lower() == "love":
            similarities = [
                "Considered a supreme virtue",
                "Essential for spiritual life",
                "Expressed through compassion and kindness"
            ]
            differences = [
                "Christianity: Agape (selfless, unconditional love) as highest form",
                "Islam: Love for Allah and creation as act of worship",
                "Judaism: Love (ahavah) as covenantal loyalty",
                "Hinduism: Prema (divine love) as path to union with Brahman",
                "Buddhism: Metta (loving-kindness) as one of Four Immeasurables"
            ]
        else:
            similarities = [f"All traditions have teachings about {concept}"]
            differences = [f"Each tradition understands {concept} differently based on their worldview"]
        
        return similarities, differences

    def _get_unique_concepts(self, concept: str, religions: List[Religion]) -> Dict[str, List[str]]:
        """Get unique concepts for each religion."""
        unique_concepts = {}
        
        for religion in religions:
            unique_concepts[religion.value] = []
        
        # Simplified examples
        if concept.lower() == "salvation":
            unique_concepts[Religion.CHRISTIANITY.value] = [
                "Justification by faith",
                "Sanctification process",
                "Glorification in heaven"
            ]
            unique_concepts[Religion.ISLAM.value] = [
                "Submission to Allah's will",
                "Balance of faith and good deeds",
                "Paradise (Jannah) as reward"
            ]
            unique_concepts[Religion.JUDAISM.value] = [
                "Living according to Torah",
                "Tikkun Olam (repairing the world)",
                "Olam Haba (world to come)"
            ]
        elif concept.lower() == "enlightenment":
            unique_concepts[Religion.BUDDHISM.value] = [
                "Nirvana (cessation of suffering)",
                "Four Noble Truths",
                "Eightfold Path"
            ]
            unique_concepts[Religion.HINDUISM.value] = [
                "Moksha (liberation from cycle of rebirth)",
                "Self-realization (Atman = Brahman)",
                "Yoga and meditation practices"
            ]
        else:
            for religion in religions:
                unique_concepts[religion.value] = [f"Unique {religion.value} perspective on {concept}"]
        
        return unique_concepts

    def _get_shared_values(self, religions: List[Religion]) -> List[str]:
        """Get shared values across religions."""
        shared_values = [
            "Compassion for others",
            "Commitment to truth",
            "Practice of charity/giving",
            "Value of human life",
            "Importance of community",
            "Call to moral integrity",
            "Practice of prayer or meditation",
            "Respect for sacred texts",
            "Observance of holy days",
            "Ethical treatment of animals and environment"
        ]
        
        return shared_values

    def _get_divergent_practices(self, religions: List[Religion]) -> List[str]:
        """Get divergent practices across religions."""
        divergent = [
            "Views on afterlife and salvation",
            "Practices of worship and ritual",
            "Dietary laws and restrictions",
            "Views on gender roles and leadership",
            "Approaches to religious pluralism",
            "Practices of pilgrimage",
            "Fasting traditions and observances",
            "Views on sexuality and marriage",
            "Attitudes toward religious art and imagery",
            "Approaches to religious authority and leadership"
        ]
        
        return divergent

    def _generate_theological_insights(
        self,
        concept: str,
        religions: List[Religion]
    ) -> List[str]:
        """Generate theological insights from comparative study."""
        insights = [
            f"Different traditions approach {concept} from distinct metaphysical foundations",
            f"Understanding {concept} requires examining each tradition's scriptural basis",
            f"Dialogue about {concept} can reveal both common human aspirations and unique answers",
            f"The diversity in understanding {concept} reflects cultural and historical contexts",
            f"Studying {concept} across traditions enriches one's own theological perspective"
        ]
        
        return insights

    def _generate_practical_implications(
        self,
        concept: str,
        religions: List[Religion]
    ) -> List[str]:
        """Generate practical implications from comparative study."""
        implications = [
            f"Interfaith dialogue about {concept} promotes mutual understanding",
            f"Practical applications of {concept} vary significantly across traditions",
            f"Respecting different approaches to {concept} enhances religious liberty",
            f"Common ground on {concept} can serve as basis for cooperation",
            f"Differences in {concept} remind us of the complexity of human spirituality"
        ]
        
        return implications

    def _conduct_literature_search(
        self,
        question: str,
        religion_focus: Optional[Religion],
        scripture_focus: Optional[ScriptureType]
    ) -> List[str]:
        """Simulate literature search for research."""
        sources = [
            f"Anchor Yale Bible Dictionary (entry on '{question}')",
            f"Encyclopedia of Religion (volume on {religion_focus.value if religion_focus else 'comparative'})",
            f"Journal of Biblical Literature (recent articles on '{question}')",
            f"Numen: International Review for the History of Religions",
            f"Harvard Theological Review",
            f"Religious Studies Review",
        ]
        
        # Filter by focus if specified
        if religion_focus:
            sources = [s for s in sources if religion_focus.value in s.lower() or 'comparative' in s.lower()]
        
        return sources[:5]  # Return top 5

    def _analyze_findings(self, question: str, sources: List[str]) -> List[str]:
        """Analyze research findings."""
        findings = [
            f"Scholarly consensus indicates {question} has been interpreted in multiple ways",
            f"Historical context significantly influences understanding of {question}",
            f"Different scholarly traditions emphasize different aspects of {question}",
            f"Contemporary applications of {question} continue to evolve",
            f"The question of {question} remains relevant to modern religious practice"
        ]
        
        return findings

    def _assess_confidence(self, findings: List[str]) -> str:
        """Assess confidence level of research findings."""
        # Simplified
        if len(findings) >= 4:
            return "high"
        elif len(findings) >= 2:
            return "medium"
        else:
            return "low"

    def _format_sources(self, sources: List[str]) -> List[Dict[str, str]]:
        """Format sources for research output."""
        formatted = []
        for i, source in enumerate(sources):
            formatted.append({
                "id": f"src-{i+1}",
                "reference": source,
                "type": "academic source",
                "accessed": datetime.utcnow().strftime('%Y-%m-%d')
            })
        
        return formatted

    def get_state(self) -> Dict[str, Any]:
        """Get agent state summary."""
        return {
            'agent_id': self.agent_id,
            'texts_count': len(self.texts),
            'quote_analyses_count': len(self.quote_analyses),
            'comparative_studies_count': len(self.comparative_studies),
            'research_queries_count': len(self.research_queries),
            'religions_covered': len(set(t.religion for t in self.texts.values())),
            'scripture_types': len(set(t.scripture_type for t in self.texts.values())),
        }


# ============================================
# Factory Functions
# ============================================

def create_biblical_scholar_agent(
    agent_id: Optional[str] = None,
    name: Optional[str] = None
) -> BiblicalScholarAgent:
    """Create a biblical scholar agent."""
    agent = BiblicalScholarAgent(agent_id=agent_id or "biblical-scholar-agent")
    if name:
        agent.name = name
    return agent