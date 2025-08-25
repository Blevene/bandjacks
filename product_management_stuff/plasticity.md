Skip to content
Chat history

You said:
Is it possible to model neuro plasticity in a knowledge graph without introducing recency bias?
ChatGPT said:
Could you clarify what you mean by modeling neuroplasticity in a knowledge graph? For example:

Are you referring to modeling changes in brain connectivity or function over time?

Is the knowledge graph meant to represent human learning processes, neural connections, or something else?

What kind of data are you using (e.g., neuroscience literature, brain imaging data, user learning data)?

By “recency bias,” are you referring to a technical issue in the data model or a cognitive bias you're trying to avoid in interpreting the graph?

A bit more context will help me give you a more useful answer.

You said:
The knowledge graph is modeled threat intelligence data using Stix from MITRE. We want to use this graph to discover and model attack patterns based on previous experience and from novel inference. We don’t want to introduce recency bias in the form of overweighting techniques that have been most recently recalled.
ChatGPT said:
Thanks for the clarification. I’ll look into how to model learning and adaptation in a threat intelligence knowledge graph using STIX and MITRE data, while avoiding recency bias—specifically ensuring that older yet relevant attack techniques are not underweighted compared to more recent ones.

I’ll review approaches in knowledge graph evolution, neuroplastic modeling analogs, and bias mitigation techniques in inference systems. I’ll let you know when the research is ready.

Research completed in 5m · 24 sources · 106 searches
Modeling Neuroplasticity in STIX Threat Graphs Without Recency Bias

Adaptive Knowledge Graphs for Evolving Cyber Threat Intelligence
Cyber threat intelligence (CTI) is inherently dynamic – new attack techniques emerge, adversaries evolve their tactics, and old methods sometimes resurface. A static knowledge graph built on STIX (Structured Threat Information eXpression) data can quickly become outdated in such an environment
okoone.com
. To stay ahead, knowledge graphs must behave in a neuroplasticity-like manner: continually adapting to new information while retaining important historical knowledge. This ensures that novel attack patterns can be discovered by relating them to past techniques, without overweighting recent trends at the expense of older but significant patterns. Below, we explore methods for building a dynamically evolving CTI knowledge graph, strategies to incorporate historical attack data without introducing recency bias, analogues to neuroplasticity in knowledge graph systems, bias mitigation techniques, and tools/frameworks that support these goals.
Dynamically Evolving Knowledge Graphs in Cybersecurity
Need for Adaptivity: Traditional STIX-based intelligence sharing provides a common data format, but on its own it offers a static snapshot of threats
okoone.com
. Modern threats “mutate” rapidly and do not follow predictable patterns
okoone.com
. A CTI knowledge graph must therefore update continuously as new data arrives – integrating fresh indicators, tactics, and relationships – to maintain situational awareness. In practice, this means new STIX objects (e.g. Indicators, Attack Patterns, Intrusion Sets from MITRE ATT&CK) are ingested into the graph as they are observed.
Dynamic Attack Graphs: In enterprise defense, graph-based models like attack graphs have been used to represent evolving attack paths through networks. For example, MITRE’s CyGraph system builds a property-graph of network assets, vulnerabilities, and observed events. As new intrusion alerts or sensor events occur, they are ingested and correlated on the graph, updating the picture of possible attack paths in real time
neo4j.com
neo4j.com
. The “dynamically evolving attack graph provides context for reacting appropriately to attacks and protecting mission-critical assets”
neo4j.com
 – illustrating how a graph that updates with the latest data can improve decision support.
Flexible Schema for Evolution: Unlike rigid relational schemas, graph representations allow the model to expand fluidly with new entity types or relationships. In CyGraph’s design, the schema is “free to evolve with the data sources,” simply by adding new node or edge types as needed
neo4j.com
. This flexibility is crucial for CTI, where novel attack techniques or IoCs (Indicators of Compromise) might introduce previously unseen entities/relations. A knowledge graph built on a semantic schema (ontologies like the Cyber Threat Intelligence Ontology, etc.) can be extended when new concepts arise, without breaking existing structure.
Temporal Information: One approach is to treat the knowledge graph as a Temporal Knowledge Graph (TKG), where each edge or fact has a timestamp or validity interval. Rather than a single static graph, we have a series of snapshots or a time-annotated multi-relational graph. This enables time-based queries (e.g. “was this technique used in the last year?”) and provides a backbone for temporal reasoning. It also allows the system to maintain historical states of the knowledge graph (for example, snapshots per month) which can help detect how attack patterns change over time.
Graph Stream Processing: In implementation, frameworks exist for handling streaming graph updates. For instance, libraries like PyTorch Geometric Temporal support dynamic graph neural networks by processing data as a sequence of graph snapshots
pytorch-geometric-temporal.readthedocs.io
. This makes it easier to train models or run algorithms that consider the graph’s evolution over time (e.g. link prediction on a changing graph). Similarly, graph databases (Neo4j, JanusGraph, etc.) can ingest new STIX data in real-time, and their query engines or data science libraries can continuously recompute analytics (like centrality of a new node, shortest paths, community detection for clustering related indicators, etc.) as the graph grows.
Learning from Historical Attacks without Recency Bias
A core challenge in an adaptive CTI knowledge graph is continuously learning from new incidents while not “forgetting” past attack techniques. Recent high-profile threats might dominate the data feed, but many “older” tactics remain relevant (or may reappear). Recency bias – overvaluing the latest evidence – can mislead analysis, causing the system to ignore historically significant patterns. Here are methods to incorporate historical data effectively:
Weighted Relationship Strengths: Instead of treating all graph edges as static facts, we can assign each relationship a strength or confidence score that evolves over time. New evidence reinforces a relationship, while lack of recent evidence causes a gradual decay in strength
reddit.com
blog.gopenai.com
. This is analogous to adjusting synaptic weights in a brain. For example, if many reports over the years link a threat actor to a certain exploit technique, the actor→technique edge in the graph could carry a high confidence value. If that link hasn’t been observed in a long time, its weight might decay slightly, but not disappear entirely. Using a memory decay function on edges (with a slow exponential decay) ensures older connections “age” gracefully rather than being abruptly forgotten
reddit.com
. Crucially, a minimum floor or consolidation threshold can be set so that once a relationship has been strongly established, it never decays below a baseline
blog.gopenai.com
. This prevents important historical links from ever dropping to zero influence.
Episodic vs. Semantic Memory: In cognitive terms, we can distinguish episodic events from semantic knowledge. Episodic memory in this context would be the specific observed attacks (with time and context), whereas semantic memory is the distilled knowledge about attacker techniques and behaviors in general. One modeling approach is to store individual incidents as time-stamped relations (e.g. each intrusion attempt is an instance of Group X uses Technique Y at time t), and separately maintain an aggregated link that represents the long-term association between X and Y
arxiv.org
. For instance, using STIX, one could record each sighting of a TTP (Tactic/Technique/Procedure) by an actor as its own STIX ObservedData or Incident (with timestamps), while also incrementing a counter or confidence score on a more permanent relationship node between that actor and the technique. The aggregated link thus captures historical frequency. Importantly, one can introduce a gentle decay on the aggregate if no new sightings occur
arxiv.org
, but because it accumulated evidence from the past, it will not be overshadowed entirely by a flurry of recent events on other techniques.
Experience Replay and Ensemble Learning: Borrowing from machine learning continual learning, one strategy is retraining or updating models with a mix of old and new data. For example, a link prediction model or rule-based reasoning system could periodically re-evaluate predictions using the full history of the graph, not just the latest slice. Some systems maintain a cache of historical samples (past attack cases) and intermix them when learning from new samples, to prevent the model from skewing toward recent patterns. This is akin to rehearsal methods that replay old experiences to avoid catastrophic forgetting.
Memory-Triggered Reasoning: Recent research on temporal KGs has pointed out that many models tend to focus mostly on the most recent facts and overlook earlier data
link.springer.com
. One solution is a two-stage reasoning: use earlier historical facts to initialize the state, then incorporate the latest facts for refinement. For example, Zhao et al. (2023) propose a memory-triggered approach that first establishes each entity’s representation based on long-term historical context, then updates it with recent events
link.springer.com
. This led to better extrapolation performance, since the model wasn’t blind to older patterns when predicting future events. In a CTI setting, this could mean that in predicting the next likely attack technique for a threat group, the system first recalls the group’s full historical technique profile (perhaps giving some weight even to techniques not seen in a while), and then adjusts predictions based on any new trends. Such an approach explicitly mitigates recency bias by ensuring historical context is always factored into the inference.
Multi-Scale Time Windows: Another method is to design inference rules or graph queries that operate at multiple timescales. For instance, one could run analytics on a “recent window” (e.g. last 3 months of data) and a “long-term window” (last 10 years), then combine the insights. This is analogous to having short-term and long-term memory. By comparing results, one can detect if a pattern is truly novel or just a resurgence of an older pattern. Multi-scale weighting can also be applied: e.g. 50% weight to recent evidence, 50% to historical evidence in decision-making, tuned to avoid overemphasizing recency.
Avoiding Flush-and-Relearn: It’s important that the knowledge graph never fully resets or discards older nodes/links just because they haven’t appeared lately. A bias can creep in if the system’s state is primarily determined by the latest data dump. Instead, older data should remain accessible (perhaps marked as dormant or lower priority, but present). For example, an automated threat hunting system might keep a knowledge base of MITRE ATT&CK techniques including those last seen years ago, so that if an alert comes in that matches an old technique, the system can still recognize it. This way, historically significant but infrequent patterns remain “on the radar.”
Neuroplasticity Analogues in Knowledge Graph Systems
The term neuroplasticity refers to the brain’s ability to rewire itself – strengthening some synapses and weakening or pruning others – in response to learning and experience. We can draw several analogies between neural plasticity and an adaptive knowledge graph:
Hebbian Learning (“Fire Together, Wire Together”): In neural networks, Hebbian plasticity means frequently co-activated neurons develop stronger connections. The KG analogue is to strengthen relationships that consistently occur together
blog.gopenai.com
. If, for example, malware A and exploit B are often seen in the same campaigns, a Hebbian approach would increase the weight or confidence of the link between A and B each time they co-occur. Over time, this creates a robust association in the graph that can help predict that if one is observed, the other might follow. This dynamic adjustment of edge weights is akin to the “learning” of the graph. Some experimental systems implement this by incrementing a relationship’s strength by a small amount whenever it’s activated/observed
blog.gopenai.com
.
Synaptic Pruning and Forgetting: Just as brains remove rarely-used synaptic connections, knowledge graphs can decay or remove stale edges to improve efficiency and relevance
blog.gopenai.com
. For instance, if a certain threat actor was once linked to an IP address or C2 server that hasn’t been active in many years, that specific linkage might be gradually down-weighted or even pruned from the active graph (while perhaps retaining it in an archive for completeness). Pruning “weakly-utilized pathways” focuses the graph on salient information
blog.gopenai.com
. The key is to do this gradually and carefully, to avoid losing information that might become relevant again. Introducing a slow decay and a threshold for complete removal (only prune if weight falls below a very low threshold) ensures that only truly obsolete or spurious connections are removed. This corresponds to homeostatic plasticity mechanisms: the system maintains overall stability by damping unused connections so that new ones can form without the graph growing unbounded
blog.gopenai.com
blog.gopenai.com
.
Stability-Plasticity Trade-off: In continual learning, there’s a well-known tension between plasticity (learning new knowledge) and stability (retaining old knowledge). Achieving a balance is analogous to how the brain learns throughout life without forgetting basic skills. In knowledge graphs, we want to allow significant updates when novel info arrives (high plasticity), but also preserve core, validated knowledge (stability). Research has begun borrowing bio-inspired ideas to manage this trade-off. For example, a 2025 study by Song et al. introduced a dual-mask mechanism for knowledge graph embeddings, inspired by neuronal activation and inhibition
proceedings.mlr.press
. This model (CMKGE) effectively “masks” certain parts of the learned representation to protect important old knowledge while new facts are learned, mimicking how inhibitory neurons might protect established circuits when new stimuli are processed
proceedings.mlr.press
. The result is a system that filters and retains critical old knowledge to prevent forgetting, yet remains flexible enough to integrate new patterns
proceedings.mlr.press
. Similarly, other approaches like Parameter Isolation in graph neural networks allocate dedicated parameters for new knowledge while leaving weights responsible for old knowledge unchanged
themoonlight.io
themoonlight.io
. These techniques echo the concept of different neural pathways handling new vs. old tasks.
Metaplasticity: In neuroscience, metaplasticity refers to the plasticity of plasticity – the brain’s ability to modulate how easily it learns or forgets based on context. In a KG context, one could implement rules that adjust the learning rate for the graph. For example, during periods of rapid change (say a new exploit is causing widespread incidents), the system might temporarily increase its “plasticity” (e.g., faster update of weights, shorter decay half-life to incorporate new data quickly). Conversely, if an observed pattern is suspected to be noise or deception (false flags), the system might be more conservative (lower plasticity) to avoid over-adjusting. Designing such dynamic adjustment policies ensures the KG remains neither too rigid nor too volatile.
Consolidation of Knowledge: The brain consolidates short-term memories into long-term storage during processes like sleep. Analogously, a KG system can have a routine to consolidate frequently observed patterns into permanent knowledge. For example, after observing a new attack technique multiple times across different contexts, the system could elevate it to a confirmed TTP in its ontology (if not already there). This might involve increasing its weight to a “stable” level that decays very slowly going forward
blog.gopenai.com
. In practice, this could be a batch job that runs periodically to review edges whose strength has exceeded some threshold and then flags them as long-term knowledge (perhaps even locking them or backing them up separately to ensure they are not perturbed by everyday updates).
Neuromorphic Algorithms: Some experimental works explicitly implement neural plasticity rules in knowledge representations. For instance, Micheal Bee and colleagues (2024) demonstrated a prototype where a knowledge graph’s edges adjust via Hebbian-like rules and homeostatic mechanisms
blog.gopenai.com
blog.gopenai.com
. They reported that the system could successfully modify its own graph structure based on usage patterns – essentially a proof-of-concept of neuroplasticity in a symbolic knowledge base
blog.gopenai.com
blog.gopenai.com
. While these are early-stage explorations, they highlight that principles like spike-timing dependent plasticity, multi-scale decay, and adaptive learning rates can be translated into graph algorithms
blog.gopenai.com
. Such analogues provide inspiration for how a CTI knowledge graph might autonomously reweight and reorganize connections as it “experiences” more cyber events.
Mitigating Recency Bias in Inference
When drawing conclusions or making predictions from an evolving knowledge graph, one must guard against recency bias – the tendency to give disproportionate importance to the newest data. Below are strategies to mitigate this bias during graph-based inference or learning:
Regularization to Preserve Past Knowledge: In machine learning models applied to the KG (e.g., link prediction models or graph embeddings updated over time), one can add regularization terms that penalize drastic changes to parameters associated with well-established facts. For example, an embedding for a known long-term relationship might be constrained not to move too far during each update. Techniques like Elastic Weight Consolidation (EWC), which in continual learning penalize changes to important weights, can be adapted for graph embeddings – giving a stability anchor to historically significant relations. Although straightforward regularization alone has limitations
research.manchester.ac.uk
, it can be part of a larger solution.
Replay and Mixed Training Batches: As mentioned, always include a slice of historical data when training models on new data. If using a graph neural network for, say, attack technique prediction, ensure the training batches contain some edges/triplets from older time periods. This prevents the model from solely optimizing for recent distribution. Some frameworks use experience replay buffers for graphs, sampling edges from different time points.
Bias Detection Tests: It can be useful to explicitly test the system for recency bias. For instance, evaluate the model’s predictions on scenarios that require historical knowledge. If a model only trained on recent data fails to predict an attack that uses an old technique (which was present in older data), that flags an issue. By including such test cases in validation (e.g., hold out some historical patterns and see if the model remembers them), one can tune the system accordingly.
Adversarial Debiasing: Advanced techniques involve training adversarial models to remove unwanted biases. In graph terms, a model could be encouraged to perform well without simply relying on timestamp cues. A 2021 study, for example, used an adversarial loss to force a GNN to not overly favor recent transactions in crypto fraud detection
arxiv.org
. The idea is to train the model to maximize predictive performance while a secondary adversary tries to guess the recency of the data it’s using; if the adversary fails, it means the model isn’t encoding a pure recency signal. While this is complex, it illustrates that one can algorithmically push the system toward a more balanced consideration of old vs. new information.
Temporal Reasoning Logic: Incorporating explicit temporal logic rules can mitigate bias. For example, one could encode a rule like: “If an attack pattern has not been seen recently, that does not reduce its likelihood of reoccurrence unless a compensating control has rendered it obsolete.” This reminds the inference engine that “absence of evidence is not evidence of absence.” Similarly, using temporal ontology that relates techniques over eras can help – e.g., mapping deprecated techniques to their modern variants ensures that knowledge is carried forward in a new form rather than dropped.
Human-in-the-Loop Adjustments: In practice, analysts can provide feedback to the system to correct biases. If the knowledge graph suggests an intelligence hypothesis overly focused on the latest malware, an analyst might tag some older campaign patterns as “still relevant.” The system can treat this feedback as a signal to boost the weight of older connections. Over time, active learning with expert input can calibrate the balance.
It’s worth noting that research in continual graph learning is ongoing, and achieving an optimal balance is hard. Studies have found that many continual knowledge graph embedding (CKGE) methods either “struggle to retain previously learned knowledge, leading to severe forgetting, or fail to effectively learn new triples,” and even generic CL strategies like EWC or replay have trouble fully solving the balance in dynamic KGs
research.manchester.ac.uk
. This underscores the importance of combining multiple strategies and carefully designing the system to be resilient against bias.
Tools and Frameworks Supporting Adaptive Knowledge Graphs
Building a neuroplastic, bias-mitigating knowledge graph for threat intelligence can leverage several tools and frameworks:
Knowledge Graph Embeddings (Dynamic/TKGE models): Traditional KG embedding algorithms (TransE, DistMult, etc.) assume static triples. However, there are now Temporal KG Embedding models that incorporate time. For example, Know-Evolve (Trivedi et al. 2017) introduced a deep evolutionary knowledge network that learns non-linearly evolving entity representations over time
proceedings.mlr.press
. It treats the occurrence of an event as a point process influenced by the entity embeddings, enabling prediction of not just what relations might form but when they might occur
proceedings.mlr.press
. Other models like TTransE (Leblay & Chekol 2018), HyTE (Dasgupta et al. 2018), ChronoR (Sadeghian et al. 2021), and more recent ones use various methods (rotations in time, temporal regularization, etc.) to embed time-aware relationships. Using such embeddings, one can perform link prediction that naturally accounts for temporal patterns – for instance, inferring a likely future association between an actor and a technique by looking at the vector dynamics, without short-changing older associations.
Graph Neural Networks with Memory: Graph Neural Network frameworks have emerged that specifically handle streaming graph data. Temporal Graph Networks (TGN) are one example – they maintain a memory for each node that updates with events, and use message passing in a temporal order. Libraries like PyTorch Geometric Temporal implement TGN and other dynamic GNN models, offering “state-of-the-art deep learning methods to process spatio-temporal signals” on dynamic graphs
pytorch-geometric-temporal.readthedocs.io
. These can be applied to CTI KGs to predict evolving threats or to classify nodes/edges (e.g., flag a newly seen IP as malicious based on temporal interaction patterns). Importantly, many of these models include time decay functions or attention mechanisms that can be tuned to avoid pure recency focus (for example, an attention mechanism can be designed to weight messages by recency but capped so that older messages still contribute).
Continual Learning Frameworks: As noted earlier, new research like CMKGE (Continual Masked KGE) by Song et al. is bringing bio-inspired continual learning to KGs
proceedings.mlr.press
. While code might not be publicly available yet, the concepts can be implemented using deep learning libraries (TensorFlow/PyTorch) with custom training loops. There are also open libraries for continual learning on graphs; some researchers have released benchmarks (e.g., the PS-CKGE benchmark with pattern shifts
research.manchester.ac.uk
research.manchester.ac.uk
) and baseline implementations of techniques like parameter isolation (e.g., PI-GNN), knowledge distillation for graphs, etc. Utilizing these can jump-start development of a system that incrementally learns from CTI data feeds.
Graph Databases and Query Engines: On the infrastructure side, graph databases (Neo4j, TigerGraph, Amazon Neptune, etc.) are well-suited to store STIX-based knowledge graphs. They often support temporal properties either natively or through data modeling conventions (e.g., adding validity date ranges to relationships). With these, one can query historical and current data uniformly. For example, a Cypher or Gremlin query could find “all threat groups who used technique X in the 5 years before technique Y appeared” to discover precursors of a novel technique. Neo4j’s Graph Data Science library can run algorithms like similarity, PageRank, or link prediction on the graph; by running these algorithms at different time slices or weighting edges by age, analysts can uncover trends without bias toward the latest. Some platforms (e.g., OpenCTI by the French SEKOIA/Filigran team) natively combine a graph backend with CTI data ingestion and provide visual analytics, which can serve as a foundation to build in adaptive weighting (via custom scoring of relationships).
Temporal Reasoning and Rule Engines: In addition to learned embeddings, symbolic reasoning on the graph can capture expert knowledge about time. Tools like OWL2 with SWRL rules or custom reasoning engines can encode temporal rules (e.g., “if an APT was active in region X a decade ago, any resurgence of similar activity in region X should raise an alert even if it’s been quiet”). There are research prototypes integrating logical reasoning with embeddings for temporal knowledge graphs, which could be applied to express long-term vs short-term knowledge explicitly. For instance, one could maintain a rule-based system that flags when an old pattern reoccurs after a long gap – effectively counteracting any machine-learned bias that might have downplayed that pattern.
Hybrid AI Systems (Neuro-symbolic): The combination of graph knowledge with modern AI like language models is also promising. Large Language Models (LLMs) can help ingest unstructured threat reports into the knowledge graph (extracting entities/relations)
okoone.com
, but beyond that, they can also be used to reason with the graph in natural language. For example, an LLM could be prompted with graph-derived facts from both recent and older data, asking it to hypothesize about new threats. Ensuring the prompt or retrieval step fetches a mix of historical and recent facts (a sort of Graph-RAG – Retrieval-Augmented Generation using graphs) can mitigate recency bias in the answers. Frameworks are being developed to combine graph memories with LLMs to create more temporal agents that respect the timeline of facts
cookbook.openai.com
. While still experimental, this approach can emulate an analyst that recalls decades of threat history when analyzing current events.
Visualization and User Oversight: Finally, tools that visualize the knowledge graph over time (temporal graph dashboards) can help humans spot biases. If a dashboard shows the “activation” of nodes/edges over time (e.g., heatmaps of which techniques are currently hot vs historically), an analyst can notice if the system’s focus has narrowed too much on the recent hot spots. Interactive graph visualization (as provided by many CTI platforms) allows the expert to pull in historical connections on demand, effectively overriding any automated bias. The system can learn from this by subsequently adjusting its internal weights to more prominently feature those connections in the future.
Example: Preserving Historical Patterns in Practice
To illustrate, imagine a knowledge graph where nodes include Threat Actor groups, Tools/Malware, Techniques (from MITRE ATT&CK), and Campaign events, with relationships like uses, targets, associated-with, etc. Suppose Group A heavily used Technique T1 from 2015–2018, but in recent years has favored newer techniques T2 and T3. A recency-biased system might all but ignore T1 when analyzing Group A today. An adaptive approach, however, would handle it as follows:
The edge (Group A –uses– T1) would have a high confidence due to past data. Even though no new events for T1 occurred lately, a decay function only slightly reduced the weight. It might still be, say, 0.8 on a 0-1 scale, whereas the newer edges (A–T2, A–T3) are at 0.9 after active use. T1’s edge might decay toward 0.7 over a very long period if unused, but never to 0.0 because it crossed a consolidation threshold from years of evidence
blog.gopenai.com
.
The system keeps a timestamped log of last seen use of T1 by Group A (say last observed in 2018). If a new campaign in 2025 shows Group A reverting to T1 (perhaps due to an opportunity where that old technique is effective again), the knowledge graph “fires together” those nodes and immediately strengthens the link once more (weights go back up). The prior existence of the connection means the system can quickly associate the event with known patterns (as opposed to treating it as a completely new, unknown link).
In forecasting Group A’s next moves, the reasoning component doesn’t purely rely on the frequency of use in 2024–2025 (which would highlight T2, T3). Because a memory-triggered model was used, the latent representation of Group A still encodes T1 from its historical profile
link.springer.com
link.springer.com
. The inference might yield: “Group A is likely to use T2 or T3, but there is also a non-negligible chance of T1 reappearing given the right circumstances,” which is a richer prediction.
Analysts reviewing the KG can see a timeline of Group A’s techniques: a burst of T1 in the past, quiet for a while, then current use of T2/T3. This temporal context is crucial. If an analyst knows T1 is an old method that might succeed against organizations that haven’t updated certain defenses, they might proactively ensure those defenses are in place, even though T1 is “old”. The knowledge graph, by retaining the link and perhaps attaching notes or references to past incidents, surfaces that insight.
In summary, the goal is to make the knowledge graph learn and adapt like a brain – strengthening connections through repeated exposure, pruning away noise, generalizing from past experiences to infer future threats – while systematically avoiding the trap of only paying attention to the latest data. By combining dynamic graph techniques with bias mitigation strategies and drawing inspiration from neuroplasticity, CTI analysts and systems can stay prepared for both the cutting-edge attack of tomorrow and the reemergence of an older tactic from yesterday. References:
Noel, S. (2015). CyGraph: Cybersecurity Situational Awareness That’s More Scalable, Flexible & Comprehensive. Neo4j Blog – Describes a dynamic attack graph approach for merging network data, where “the dynamically evolving attack graph provides context for reacting appropriately to attacks”
neo4j.com
 and the schema can evolve with new data
neo4j.com
.
Okoone (2025). What comes after STIX in cybersecurity intelligence. – Highlights the need for moving beyond static STIX data to dynamic, context-rich knowledge graphs that can anticipate evolving threats
okoone.com
.
Zhao, M. et al. (2023). Temporal KG reasoning triggered by memories. – Discusses how many temporal KG models focus too much on recent data and overlook earlier facts, and proposes using earlier historical facts to initialize representations, then update with recent facts
link.springer.com
link.springer.com
 to improve extrapolation.
Micheal Bee & Claude Sonnet (2024). Implementing Neural Plasticity in AI Knowledge Systems. – A blog demonstrating a knowledge graph with Hebbian learning (strengthening frequently used connections) and decay/pruning for infrequent ones, with mechanisms for stability (consolidation of strong connections)
blog.gopenai.com
blog.gopenai.com
.
Song, A. et al. (2025). Orchestrating Plasticity and Stability: A Continual KGE Framework with Bio-Inspired Dual-Mask Mechanism. – Introduces a continual learning approach for knowledge graph embeddings that uses a dual-mask (inhibitory and excitatory) to retain “critical old knowledge” while learning new, mimicking neural signal propagation
proceedings.mlr.press
.
Tian, Z. et al. (2024). Continual Learning on Graphs: A Survey. – A comprehensive survey of techniques for continual graph learning, discussing challenges like catastrophic forgetting and highlighting approaches (e.g., parameter isolation, experience replay) to balance learning and retention
research.manchester.ac.uk
.
PyTorch Geometric Temporal (2021). Temporal Graph Neural Network Library. – Open-source library providing implementations of dynamic GNNs and temporal graph learning methods
pytorch-geometric-temporal.readthedocs.io
, useful for building models that learn from time-evolving graph data such as CTI knowledge graphs.
Trivedi, R. et al. (2017). Know-Evolve: Deep Temporal Reasoning for Dynamic Knowledge Graphs. – Early work on dynamic KG embeddings that learns evolving entity representations over time
proceedings.mlr.press
, enabling prediction of new events and their timing by modeling the temporal point process of graph changes.






Sources
You said:
Can you turn this into a more detailed, trackable execution plan? 

Edge Weighting and Plasticity (Hebbian + GNN priors)
	•	Duration: 2 weeks
	•	Goal: Produce stable, evidence‑weighted technique edges that resist recency bias and improve simulation accuracy by using Hebbian updates, slow decay, consolidation floors, tactic proximity, defense reduction, and optional GNN priors.
Scope
	•	Edge types and properties
	•	NEXT: (:AttackPattern)-[:NEXT {w_hebb, w_recent, w_long, w_imputed, w_gnn?, w_final, updated_at}]→(:AttackPattern)
	•	CO_OCCURS: (:AttackPattern)-[:CO_OCCURS {w_hebb, w_recent, w_long, w_imputed, w_gnn?, w_final, updated_at}]→(:AttackPattern) (unordered pairs)
	•	Jobs
	•	Nightly plasticity job computes co‑occurrence, applies Hebbian updates, decays, and blends into w_final
	•	Weekly optional GNN prior refresh (edge regression) and blend into w_final
	•	Consumers
	•	Simulator: prefer w_final for transitions; fallback to historical avg(n.p)
	•	Flow builder: boost probability if w_final is high
	•	APIs
	•	Read-only weight inspection endpoints for observability and UI
Non-goals (this sprint)
	•	Full-blown temporal KGE; production-grade retraining pipelines; UI visualizations beyond basic inspection.
Data model and configuration
	•	Relationship properties default values on create: w_hebb=0, w_recent=0, w_long=0, w_imputed=0, w_final=0, updated_at=timestamp()
	•	Settings
	•	plasticity.consolidation_floor=0.05
	•	plasticity.recent_alpha=0.3
	•	plasticity.long_alpha=0.01
	•	plasticity.metaplastic_m=0.6 (0..1 blend recent vs long)
	•	plasticity.tactic_bonus_same=0.08
	•	plasticity.tactic_bonus_adjacent=0.05
	•	plasticity.defense_reduction_per_counter=0.15
	•	plasticity.defense_reduction_cap=0.75
	•	plasticity.enable_gnn=false
	•	plasticity.alpha_gnn=0.4 (blend weight if GNN enabled)
Implementation plan
	•	Job: Hebbian + decay + defense + tactic bonus
	•	Co-occurrence extraction (unordered pairs) per episode
	•	Update CO_OCCURS EMA buckets: w_recent = (1−αr)*w_recent + αr*1.0, w_long = (1−αl)*w_long + αl*1.0
	•	Update NEXT from observed AttackAction -[:NEXT]-> AttackAction (use avg(probability) as signal)
	•	Metaplastic blend: w_hebb = m*w_recent + (1−m)*w_long
	•	Consolidation floor: w_hebb = max(floor, w_hebb)
	•	Tactic proximity: add bonus for same/adjacent tactics to w_imputed
	•	Defense reduction: subtract capped reduction based on (:D3fendTechnique)-[:COUNTERS]->(:AttackPattern)
	•	Final: w_final = clamp(w_hebb + w_imputed − defense_reduction, 0, 1)
	•	Exclude revoked/deprecated techniques by default
	•	Optional weekly GNN prior
	•	Train lightweight GraphSAGE/edge-regressor on current NEXT and CO_OCCURS (positives) + sampled non-edges (negatives)
	•	Predict w_gnn for sparse/isolated pairs; blend: w_final = clamp((1−α)*w_final + α*w_gnn, 0, 1)
	•	Simulator integration
	•	Change AttackSimulator._get_next_techniques to read n.w_final if present; fallback to avg historical
	•	Flow builder integration
	•	In _calculate_probability, boost if (:AttackPattern)-[NEXT]->(:AttackPattern).w_final exists and is high
	•	APIs (read-only)
	•	GET /v1/analytics/weights/next/{technique_id} → top successors with w_final, components
	•	GET /v1/analytics/weights/cooccurs/{technique_id} → top co-occurs with w_final, components
Acceptance criteria
	•	Plasticity job
	•	After ingesting flows, CO_OCCURS and NEXT edges have non-zero w_hebb and w_final
	•	Consolidation floor applied: no w_hebb below floor when evidence exists
	•	Defense reduction lowers w_final when D3FEND counters exist; never below 0
	•	Excluding revoked/deprecated by default; flag toggles include them when requested
	•	Simulator
	•	With identical data, replacing avg(n.p) with w_final does not degrade basic predictions; improves stability on noisy recent data
	•	Given sparse data, transitions still produced via tactic bonus and (if enabled) GNN prior
	•	APIs
	•	Weight inspection endpoints return data in <200ms P95 for top 20 results
	•	Performance
	•	Plasticity job completes within 5 minutes for 100k actions / 10k episodes on target infra
Test plan
	•	Unit tests
	•	Hebbian update functions (EMA, blend, floor)
	•	Defense reduction and tactic bonus functions
	•	Clamp bounds and metaplasticity m behavior
	•	Integration tests (Neo4j)
	•	Build tiny episode set; run job; assert edge properties (w_recent, w_long, w_hebb, w_final)
	•	Add D3FEND counters and verify reduced w_final
	•	Revoked technique present: ensure excluded by default
	•	Simulator tests
	•	Mock edges with/without w_final; ensure selection prefers w_final
	•	API tests
	•	Snapshot tests for weight inspection endpoints
Operational runbook
	•	One-off migration
	•	Backfill relationship properties for existing NEXT edges with zeros
	•	Initialize CO_OCCURS edges (MERGE) from episodes
	•	Scheduling
	•	Run plasticity job nightly (UTC); GNN job weekly (optional)
	•	Observability
	•	Metrics: plasticity_edges_updated, avg_w_final, defense_reduction_avg, job_duration_ms, gnn_enabled
	•	Logs include trace_id and counts by edge type
	•	Rollback
	•	Keep w_* as additive properties; simulator falls back to historical avg if w_final missing
	•	Disable via plasticity.enable_gnn=false / pause job
Deliverables
	•	Plasticity job module with config and CLI entry (scripts/plasticity_run.py) and cron/example
	•	Updated AttackSimulator and FlowBuilder to consume w_final
	•	Two read-only analytics routes for weight inspection
	•	Tests (unit + integration) and minimal docs in docs/SPRINT6_PLASTICITY.md
Example Cypher building blocks
	•	See earlier proposal; reuse those MATCH/MERGE/SET patterns for CO_OCCURS, NEXT, tactic bonus, defense reduction, and w_final.
Timeline (suggested)
	•	Days 1–2: Data model props, job scaffolding, Cypher tested on sample data
	•	Days 3–4: Simulator + flow builder integration; read-only APIs
	•	Days 5–6: Tests and performance tuning; configs/flags
	•	Days 7–10: Optional GNN baseline + blending; docs; bake and QA

TL;DR
	•	Use a Hebbian-style update with slow decay and a consolidation floor to maintain evidence-weighted edges between AttackPattern nodes.
	•	Add/maintain two edge types:
	•	(:AttackPattern)-[:NEXT {w_hebb, w_recent, w_final}]->(:AttackPattern) from observed flows.
	•	(:AttackPattern)-[:CO_OCCURS {w_hebb, w_recent, w_final}]->(:AttackPattern) from episode co-presence.
	•	For isolated techniques, impute weights with a light GNN/cold-start prior (embedding similarity + tactic proximity), then blend with Hebbian weights.
	•	Consume w_final in simulation and probability calculations.
Edge weighting recipe
	•	Evidence variables per episode e:
	•	Transition signal: s_ij^e = observed transition probability p(i→j) if in flow; else 0.
	•	Co-occur signal: c_ij^e = 1 if i and j appear in the same episode; else 0.
	•	Hebbian update with decay and consolidation:
	•	Δw_hebb = η · signal − λ · w_hebb
	•	Time decay: w_hebb ← max(floor, w_hebb · exp(−γ·Δt_days))
	•	Keep dual memories to mitigate recency bias:
	•	w_recent: exponential moving average over last N days
	•	w_long: slow-decay average over all history
	•	Metaplastic blend: w_hebb = m · w_recent + (1−m) · w_long (m increases during rapid change)
	•	Cold-start/GNN prior for isolated nodes:
	•	w_imputed = β · cosine(emb_i, emb_j) + δ · I[same tactic] + ζ · I[adjacent tactics]
	•	Optionally train a lightweight GraphSAGE/edge-regressor on known edges; use predictions where evidence is sparse.
Final edge weight:
	•	w_final = clamp(w_hebb + w_imputed − defense_reduction, 0, 1)
	•	defense_reduction = min(0.15 · |COUNTERS(D3fendTechnique→i or j)|, 0.75)
Where to integrate in code
	•	Write a periodic job to materialize/update weights:
	•	Create/refresh :CO_OCCURS and update :NEXT with w_hebb, w_recent, w_long, w_imputed, w_final.
	•	Respect revoked/deprecated filtering.
	•	Consume w_final:
	•	AttackSimulator._get_next_techniques: prefer n.w_final over avg(n.p) when present.
	•	flow_builder._calculate_probability: boost if w_final between techniques is high.
Cypher snippets
	•	Maintain co-occurrence pairs (unordered) and update weightscypher// Build/update CO_OCCURS from episodesMATCH (e:AttackEpisode)WITH eMATCH (e)-[:CONTAINS]->(a:AttackAction)WITH e, collect(DISTINCT a.attack_pattern_ref) AS techsWHERE size(techs) >= 2UNWIND techs AS tAUNWIND techs AS tBWITH tA, tB WHERE tA < tBMATCH (i:AttackPattern {stix_id: tA})MATCH (j:AttackPattern {stix_id: tB})MERGE (i)-[r:CO_OCCURS]->(j)ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0, r.updated_at = timestamp()WITH r// Hebbian increment (η) and decay (λ) in one stepSET r.w_recent = 0.7*r.w_recent + 0.3*1.0     // EMA for recent windowSET r.w_long   = 0.99*r.w_long   + 0.01*1.0   // slow accumulatorWITH r, 0.6 AS mSET r.w_hebb = m*r.w_recent + (1-m)*r.w_longSET r.w_hebb = CASE WHEN r.w_hebb < 0.05 THEN 0.05 ELSE r.w_hebb END  // consolidation floorSET r.updated_at = timestamp();
	•	Update NEXT edges with blended weights (using observed n.probability if present)cypherMATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)WITH a1.attack_pattern_ref AS i, a2.attack_pattern_ref AS j, avg(coalesce(n.probability, n.p, 0.5)) AS sMATCH (ti:AttackPattern {stix_id: i})MATCH (tj:AttackPattern {stix_id: j})MERGE (ti)-[r:NEXT]->(tj)ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0WITH r, sSET r.w_recent = 0.7*r.w_recent + 0.3*s,    r.w_long   = 0.995*r.w_long + 0.005*s,    r.w_hebb   = 0.6*r.w_recent + 0.4*r.w_long;
	•	Impute priors and compute w_final with D3FEND reductioncypher// Tactic proximity bonusMATCH (i:AttackPattern)-[:HAS_TACTIC]->(ti:Tactic),      (j:AttackPattern)-[:HAS_TACTIC]->(tj:Tactic),      (i)-[r:NEXT]->(j)WITH r, ti.shortname AS t1, tj.shortname AS t2WITH r, CASE WHEN t1 = t2 THEN 0.08             WHEN t1 IN ['initial-access','execution'] AND t2 IN ['persistence','privilege-escalation'] THEN 0.05             ELSE 0.02 END AS tactic_bonus// Defense reductionMATCH (i)<-[:COUNTERS]-(d1:D3fendTechnique)MATCH (j)<-[:COUNTERS]-(d2:D3fendTechnique)WITH r, tactic_bonus, count(d1)+count(d2) AS dcountSET r.w_imputed = tactic_bonusSET r.w_final = apoc.number.clamp(r.w_hebb + r.w_imputed - least(dcount*0.15, 0.75), 0, 1);
Lightweight GNN option (optional but recommended)
	•	Train GraphSAGE (edge regression) on a projection of AttackPattern graph:
	•	Nodes: features = [text embedding, tactic one-hot, platform flags, degree, age].
	•	Positive edges: observed NEXT and CO_OCCURS; target = n.probability or 1.0.
	•	Negatives: sampled non-edges.
	•	Use predicted score as w_gnn; blend: w_final = clamp(α·w_hebb + (1−α)·w_gnn − defense_reduction, 0, 1).
	•	Run weekly; cache scores on edges to avoid runtime cost.
Scheduling/ops
	•	Add a daily cron/job:
	•	Recompute co-occurrence, update Hebbian/decay, set w_final.
	•	Optionally refresh GNN scores weekly.
	•	Gate with flags: exclude revoked/deprecated by default; keep provenance in edge props.
What this gives you
	•	Edges between techniques capture both long-run and recent evidence, don’t forget history, and degrade gracefully.
	•	Isolated/new techniques still get reasonable priors via embeddings/tactics (and optionally GNN).
	•	Simulator and flow builder can use w_final for sharper, more stable predictions, resilient to recency bias.
ChatGPT said:
Thanks for the very detailed outline. Just to confirm before I convert this into a structured execution plan: would you like the final output as a visual project plan (e.g. Gantt-style), a task breakdown for engineers (e.g. in JIRA ticket format), or a written document suitable for a sprint planning meeting? Feel free to specify format, tools used (if any), and your target audience.

You said:
Written document with embedded task breakdown, in markdown please
ChatGPT said:
Great. I’ll convert your neuroplasticity-inspired edge weighting specification into a detailed, markdown-formatted execution plan with embedded task breakdowns, milestones, and implementation guidance. This will be structured to support sprint planning and developer implementation.

I’ll let you know when it’s ready for review.

Research completed in 6m · 7 sources · 42 searches
Execution Plan for Hebbian Edge Weighting and Plasticity in Threat Simulation Graph

Edge Weighting and Plasticity (Hebbian + GNN Priors) – Execution Plan
Goal and Overview
This project is estimated to take 2 weeks. Its goal is to produce stable, evidence-weighted edges between attack techniques (nodes) that resist recency bias and improve simulation accuracy. We will achieve this by applying a Hebbian-style plasticity update with slow decay, a consolidation floor, tactic-based adjustments, defense-based reductions, and optional graph neural network (GNN) priors. In essence, we want the connections between techniques to strengthen when they frequently co-occur or transition together (a Hebbian "fire together, wire together" approach
en.wikipedia.org
) and to decay slowly over time so that historical patterns are not forgotten. New or isolated techniques will receive estimated weights using similarity-based heuristics or GNN predictions to avoid cold starts. Key Objectives:
Maintain two types of relationships between techniques in the graph: sequential transitions (:NEXT edges) and co-occurrences (:CO_OCCURS edges). Each edge carries various weight components (Hebbian short-term and long-term memories, imputed/prior weight, final combined weight, etc.).
Implement a nightly “plasticity” job that updates these edge weights based on new observations (flows/episodes), applying Hebbian learning rules (increment on co-activation, exponential decay) and adjustments like consolidation floor, tactic proximity bonuses, and defense technique penalties.
Optionally implement a weekly GNN-based job that generates prior weights for edges (using a GraphSAGE model for link prediction
stellargraph.readthedocs.io
stellargraph.readthedocs.io
) to inform connections where data is sparse, and blend these priors into the final weight.
Update the Attack Simulator and Flow Builder components to consume the new w_final weights for deciding technique transitions and calculating probabilities, respectively.
Provide read-only API endpoints to inspect the computed weights (for observability and potential UI use).
Ensure the solution is performant (e.g. the nightly job runs within a few minutes on typical data volumes) and that it improves stability of simulations (less fluctuation due to recent data spikes) without regressing accuracy.
Scope
The scope of this execution plan includes the following components:
Edge Types and Properties: Introduction of two relationship types between AttackPattern nodes: NEXT (ordered edges representing observed sequential transitions) and CO_OCCURS (undirected co-occurrence relationships for techniques seen in the same episode). Each edge will store weight components: w_hebb (Hebbian blended weight), w_recent (recent EMA contribution), w_long (long-term contribution), w_imputed (imputed/prior weight from tactics or GNN), w_final (the final combined weight used by consumers), and updated_at (timestamp of last update). These properties will be maintained and updated by the jobs described below.
Batch Jobs: A nightly plasticity job will compute co-occurrence signals from the latest episodes/flows and update the CO_OCCURS and NEXT edges accordingly (applying Hebbian increment and decay to w_recent and w_long). It will then compute blended weights (w_hebb), apply consolidation floor minima, adjust for tactic proximity (w_imputed partial), apply any defense-based reductions, and finally set w_final for each edge. Additionally, a weekly GNN prior job is in scope (configurable, optional) which trains a lightweight GraphSAGE-based model to predict link probabilities for technique pairs; those predictions (w_gnn) can be blended into w_final for edges that have sparse direct evidence. Both jobs will exclude revoked or deprecated techniques by default (unless explicitly configured otherwise).
Consumers (Simulator & Flow Builder): The Attack Simulator will be modified to use the new edge weights. Specifically, when deciding the next technique in a simulated attack sequence, it will prefer the probability given by w_final on a :NEXT edge if available, rather than the historical average probability (n.p) used previously. The Flow Builder (which constructs attack flows and calculates step probabilities) will also incorporate w_final by boosting the probability of transitions that have a high learned weight. This ensures that the learned graph influences simulation behavior, making it more realistic and less random. If w_final is missing for a given transition (e.g. new techniques with no data and no imputed prior), the system will gracefully fall back to the historical averages to maintain continuity.
APIs for Observability: We will implement read-only API endpoints to expose the weights for inspection. These might include endpoints such as GET /v1/analytics/weights/next/{technique_id} to retrieve the top successor techniques (outgoing NEXT edges from a given technique) ranked by w_final (and possibly returning the components w_hebb, w_imputed, etc. for transparency), and GET /v1/analytics/weights/cooccurs/{technique_id} to retrieve top co-occurring techniques for a given technique. These endpoints will help in debugging, UI visualizations of the technique network, and verifying that the weight updates are intuitive. They will be optimized for performance (e.g., returning top 20 results within ~200ms at the 95th percentile).
Out of Scope (Non-Goals for this Sprint): To keep the effort focused, certain aspects are explicitly not included in this sprint:
Developing a full temporal knowledge graph embedding or complex ML pipeline beyond the lightweight GNN prior. (No large-scale training infrastructure or KGE retraining in production yet.)
Advanced UI visualizations of the technique graph beyond basic weight inspection outputs. (UI work will be minimal, relying on the API outputs; a more polished visualization can be tackled in a future sprint if needed.)
Any changes to how data is ingested or fundamental changes to underlying Attack/Defense models. (We assume input data like episodes and actions are available as usual; we are only enriching how we derive technique relationships from them.)
Data Model and Configuration
Relationship Properties: When creating new :NEXT or :CO_OCCURS relationships, the system will initialize all weight properties to default values. By default on creation:
w_hebb = 0.0 (Hebbian blended weight, initially zero)
w_recent = 0.0 (Exponential moving average for recent evidence, short timescale)
w_long = 0.0 (Long-term accumulated evidence, slower timescale)
w_imputed = 0.0 (Imputed weight from non-observational priors, e.g. tactic similarity or GNN)
w_final = 0.0 (Final weight used by consumers, will be calculated)
updated_at = timestamp() (record last update time for potential debugging or staleness checks)
These properties are stored on each relationship (NEXT or CO_OCCURS) between AttackPattern nodes. Configurable Parameters: The behavior of the plasticity updates and blending is governed by a set of configuration settings (with likely defaults as below):
plasticity.consolidation_floor = 0.05 – A minimum floor value for w_hebb once any evidence has been seen. This prevents weights from decaying back to near zero after having been established, ensuring a base level of "memory."
plasticity.recent_alpha = 0.3 – The alpha (learning rate) for the recent exponential moving average (EMA). This represents how strongly new evidence influences the short-term memory. For example, using α_r = 0.3 means each new observation contributes 30% to the recent weight (and 70% is retained from previous recent value).
plasticity.long_alpha = 0.01 – The alpha for the long-term EMA. This is a much smaller value, meaning the long-term memory accumulates very slowly and retains historical evidence for a long time (e.g., 1% update on new evidence).
plasticity.metaplastic_m = 0.6 – The blending factor (m) between recent and long-term weights when computing w_hebb. A higher m leans more on recent evidence, while (1-m) weights the long-term memory. Here 0.6 means 60% recent, 40% long-term in the blended Hebbian weight.
plasticity.tactic_bonus_same = 0.08 – Bonus weight to add in w_imputed if two techniques share the same tactic category. (Techniques in the same MITRE ATT&CK tactic are likely to co-occur or transition, so we boost them slightly.)
plasticity.tactic_bonus_adjacent = 0.05 – Bonus to add if tactics are adjacent or closely related in the framework (for example, one could define adjacency based on typical attack flow, e.g. an "Initial Access" technique followed by an "Execution" or "Persistence" might be considered adjacent tactics).
plasticity.defense_reduction_per_counter = 0.15 – Reduction factor per defending countermeasure present. For each defensive technique (from MITRE D3FEND) that counters either of the two attack techniques in an edge, we reduce weight by 0.15, up to a cap.
plasticity.defense_reduction_cap = 0.75 – Maximum total reduction from defenses. Even if there are many defensive measures, the weight reduction will not exceed 0.75 (i.e., we won't reduce the weight completely to zero from defenses alone; a minimum 25% of the weight remains to account for some residual possibility).
plasticity.enable_gnn = false – Feature flag to enable the Graph Neural Network prior integration. By default it may be off (especially if the GNN model is not yet trained or validated).
plasticity.alpha_gnn = 0.4 – Blending factor for GNN prior. If GNN is enabled, the final weight could be blended as w_final = (1-α_gnn)*w_final_hebbian + α_gnn*w_gnn. For example 0.4 means 40% of the GNN-predicted weight influences the final value (applied to edges that lack strong evidence).
These settings allow tuning the balance between recent vs. long-term learning, the impact of tactics and defenses, and the influence of the GNN model. They can be adjusted based on experimental results.
Implementation Plan and Tasks
Below is a breakdown of the tasks and components that need to be implemented or modified. Each major task is outlined with sub-tasks or steps for clarity:
1. Nightly Plasticity Update Job (Hebbian Learning & Decay)
Implement a batch job (to run nightly) that processes recent attack episodes and updates the weights on :NEXT and :CO_OCCURS edges accordingly. The job will perform the following steps for each relevant relationship:
a. Extract Co-occurrence Pairs: Go through each new or updated attack episode (or all episodes nightly, depending on volume) and gather all unique pairs of techniques that co-occur in the same episode. For each episode node that contains multiple AttackAction nodes (techniques executed in that episode), produce all unordered pairs of those techniques. This will be used to update :CO_OCCURS edges. Implementation detail: Use a Cypher query to collect technique IDs in an episode and then unwind pairs. Example snippet:
// Build or update CO_OCCURS edges from episodes
MATCH (e:AttackEpisode)
  WITH e
  MATCH (e)-[:CONTAINS]->(a:AttackAction)
  WITH e, collect(DISTINCT a.attack_pattern_ref) AS techs
  WHERE size(techs) >= 2
  UNWIND techs AS tA
  UNWIND techs AS tB
  WITH tA, tB WHERE tA < tB  // ensure each unordered pair is processed once
  MATCH (i:AttackPattern {stix_id: tA})
  MATCH (j:AttackPattern {stix_id: tB})
  MERGE (i)-[r:CO_OCCURS]->(j)
    ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0, r.updated_at = timestamp()
  WITH r
  // Hebbian increment (η) and decay (λ) for co-occurrence
  SET r.w_recent = (1 - $recent_alpha) * r.w_recent + $recent_alpha * 1.0    // incorporate this co-occurrence event
  SET r.w_long   = (1 - $long_alpha)   * r.w_long   + $long_alpha   * 1.0    // long-term accumulation
  WITH r, $metaplastic_m AS m
  SET r.w_hebb = m * r.w_recent + (1 - m) * r.w_long
  SET r.w_hebb = CASE WHEN r.w_hebb < $consolidation_floor THEN $consolidation_floor ELSE r.w_hebb END
  SET r.updated_at = timestamp();
In the above pseudo-code, $recent_alpha, $long_alpha, $metaplastic_m, and $consolidation_floor are parameters coming from configuration (e.g. 0.3, 0.01, 0.6, 0.05 respectively as per defaults). The logic:
If the CO_OCCURS relationship between two techniques is new, initialize weights to 0.
Increase the recent weight (w_recent) by α_r * 1.0 (since a co-occurrence is a binary event, we treat its "signal" as 1 for that pair in this episode) and decay the existing recent weight by (1-α_r).
Increase the long-term weight (w_long) by the very small α_l * 1.0 and decay the existing by (1-α_l).
Compute a blended Hebbian weight: w_hebb = m * w_recent + (1-m) * w_long. This metaplastic approach ensures that if there’s a sudden surge or drop in co-occurrence frequency, the w_recent will capture it quickly (because of higher α_r and heavier weight in blend), but w_long ensures the historical average still anchors the value.
Apply a consolidation floor: ensure w_hebb doesn’t drop below a certain floor (e.g. 0.05) once there has been at least some evidence. This means once an edge has been established (even modestly), it never “forgets” completely; it will decay only to this minimum level, not to zero.
Update the timestamp.
b. Update Sequential Transition Edges: Similarly, update :NEXT edges representing direct sequential transitions in observed attack flows. We will use the observed probabilities of transitions as the signal. For each AttackAction that has a :NEXT relationship to a subsequent AttackAction within the same flow, accumulate an average probability of that transition (if the data has an explicit probability or frequency). Then update or create a corresponding AttackPattern -[:NEXT]-> AttackPattern edge between the technique of the first action and the technique of the second action. The update to w_recent and w_long will be similar, but using the transition probability as the increment signal instead of a fixed 1.0. Implementation detail: Example Cypher snippet to update NEXT edges from observed action-to-action transitions:
MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
  WITH a1.attack_pattern_ref AS i, a2.attack_pattern_ref AS j,
       avg(coalesce(n.probability, n.p, 0.5)) AS s  // average observed transition probability (fallback 0.5 if not provided)
  MATCH (ti:AttackPattern {stix_id: i})
  MATCH (tj:AttackPattern {stix_id: j})
  MERGE (ti)-[r:NEXT]->(tj)
    ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0
  WITH r, s
  SET r.w_recent = (1 - $recent_alpha) * r.w_recent + $recent_alpha * s,
      r.w_long   = (1 - $long_alpha)   * r.w_long   + $long_alpha   * s,
      r.w_hebb   = $metaplastic_m * r.w_recent + (1 - $metaplastic_m) * r.w_long;
This will ensure w_recent and w_long for sequential edges capture transition likelihoods (with w_recent reacting to latest patterns and w_long maintaining a running background rate). We use a possibly slightly different long_alpha for transitions (in the snippet, 0.5% = 0.005 was used, assuming transitions might accumulate even more slowly).
c. Apply Tactic Proximity Bonus: After updating w_hebb via co-occurrence or sequential events, compute an imputed weight component w_imputed based on tactic similarity of the two techniques. If two techniques belong to the same MITRE ATT&CK tactic category, add a bonus (e.g. 0.08). If they are in tactics that are commonly adjacent in attack flows, add a smaller bonus (e.g. 0.05). For any other combination, a minimal default (perhaps 0.02 or 0) could be used if we want a slight base connectivity for completely unrelated tactics. This bonus helps connect techniques that logically belong together in an attack chain even if data is sparse.
d. Apply Defense-Based Reduction: For each edge, determine if either of the connected techniques has known defensive countermeasures in the D3FEND framework. If technique A or B is countered by one or more D3fendTechnique (defensive techniques), reduce the weight. For example, if there are dcount distinct defenses that counter A or B, we subtract min(dcount * 0.15, 0.75) from the weight (capped at 0.75). This models the idea that if an attack step has strong defenses, it should be less likely or effective in a simulated chain, thus lowering the edge weight.
e. Compute Final Weight: Combine the above components into the final edge weight. The formula will be roughly:
w
f
i
n
a
l
=
clamp
(
w
h
e
b
b
+
w
i
m
p
u
t
e
d
−
defense_reduction
,
 
0
,
 
1
)
w 
final
​
 =clamp(w 
hebb
​
 +w 
imputed
​
 −defense_reduction, 0, 1)
Ensure the final value is clamped between 0 and 1 (since these represent probabilities or normalized weights). So even after adding tactic bonuses or subtracting defense penalties, we keep within [0,1]. We can do the tactic bonus and defense penalty in one Cypher pass after computing w_hebb. For example:
// Compute tactic bonus and defense reduction, then final weight
MATCH (i:AttackPattern)-[:HAS_TACTIC]->(ti:Tactic),
      (j:AttackPattern)-[:HAS_TACTIC]->(tj:Tactic),
      (i)-[r:NEXT]->(j)
WITH r, ti.shortname AS t1, tj.shortname AS t2,
     CASE 
       WHEN t1 = t2 
         THEN $tactic_bonus_same                      // same tactic bonus
       WHEN (t1,t2) IN [(["initial-access","execution"], ["persistence","privilege-escalation"])] 
         THEN $tactic_bonus_adjacent                  // example adjacent tactics pair bonus
       ELSE 0.02 
     END AS tactic_bonus
// Now account for defenses countering either technique
MATCH (i)<-[:COUNTERS]-(d1:D3fendTechnique)
MATCH (j)<-[:COUNTERS]-(d2:D3fendTechnique)
WITH r, tactic_bonus, count(DISTINCT d1) + count(DISTINCT d2) AS dcount
SET r.w_imputed = tactic_bonus
SET r.w_final = apoc.number.clamp(
                  r.w_hebb + r.w_imputed - least(dcount * $defense_reduction_per_counter, $defense_reduction_cap),
                  0, 1
                );
In the above pseudo-code, we calculate a tactic_bonus based on whether tactics are identical or in a defined adjacent set. We then count defensive techniques (d1, d2) that counter each side. We set w_imputed to the tactic bonus (note: if we later incorporate embedding similarity or GNN, that would also contribute to w_imputed). Finally, set w_final as w_hebb + w_imputed - defense_penalty, capped between 0 and 1. The apoc.number.clamp and least() (if using APOC library) handle the clamping and capping logic.
f. Exclude Revoked/Deprecated Techniques: The job will by default ignore any AttackPattern that is marked as revoked or deprecated in the MITRE ATT&CK data. This means we won't create or update edges involving those nodes, unless a configuration flag indicates to include them. This ensures our graph of techniques remains clean and focused on active techniques. (Internally, the Cypher queries might include a condition like WHERE NOT i.revoked AND NOT j.revoked etc., if such properties exist on the nodes.)
g. Scheduling and Idempotence: The nightly job should be idempotent (running it twice on the same data should yield the same weights). It should process new data since the last run. We may implement it to scan all episodes or only recent ones; if scanning all, the EMA update inherently gives less weight to older events due to decay factors. We will schedule this job to run during off-hours (e.g., every night at midnight UTC) via a cron or background worker.
Outcome of Task 1: After this job runs, the graph will have updated weights: both CO_OCCURS and NEXT edges reflecting recent learning while not forgetting past patterns. The w_final is fully computed for all edges that have any evidence or imputed values. These weights are ready to be used by the simulator and exposed via APIs.
2. Weekly GNN Prior Job (Optional)
This task involves training and applying a Graph Neural Network model (e.g., GraphSAGE) to predict the likelihood of edges between techniques, serving as a prior for edges with little or no direct evidence. This is considered optional and might be implemented if time permits or enabled later, but we outline it for completeness:
a. Graph Data Preparation: Construct a training dataset using the current technique graph. Use existing :NEXT and :CO_OCCURS edges with high w_hebb or known occurrences as positive examples (these represent technique pairs that do occur together or in sequence). For negative examples, sample pairs of techniques that are not connected by an edge (or have very low weight). Ensure a balanced or reasonable ratio of positive to negative samples.
b. Feature Engineering: Determine what features to use for the GNN. Likely features include:
Node features: could use technique text embeddings (e.g., vector representations of the technique description or name), one-hot encodings of tactic categories, flags for platforms or tags, node degree or historical frequency.
Possibly edge features: but GraphSAGE typically learns node embeddings which we combine for link prediction. We might rely on the model to learn from node neighborhoods.
c. Train GraphSAGE Link Predictor: Use a framework (such as DGL or StellarGraph) to train a GraphSAGE model to output a probability that a link exists between two nodes
stellargraph.readthedocs.io
. This usually involves:
Generating node embeddings via GraphSAGE by sampling neighbor nodes (the graph of techniques and their connections is used as the structure for GraphSAGE).
Applying a link prediction layer (e.g., take two node embeddings and apply a binary operator like concatenation or dot product, then a sigmoid to get probability).
Train with a binary cross-entropy loss on the positive vs negative edges.
The model will learn patterns of the graph, potentially generalizing to suggest new connections (e.g., it might learn that techniques under the same tactic or with similar semantic meaning should have a higher link probability, even if our Hebbian job hasn't seen them together yet).
d. Generate w_gnn Predictions: After training (which can be done offline or as part of the weekly job), use the GNN model to infer scores for candidate edges. Focus on sparse or isolated techniques – for example, pairs of techniques that share a tactic or have similar features but currently have no w_hebb evidence. The model will output a probability (or score between 0 and 1) for those pairs. Store these as w_gnn on the corresponding edges (creating the edge if it doesn’t exist in the graph already). This essentially is a way to fill in the graph with plausible connections that haven’t been observed yet.
e. Blend GNN Prior into Final Weight: If plasticity.enable_gnn is true, then update the w_final for relevant edges by blending the existing w_final (from Hebbian calculation) with the GNN prediction. For example, if alpha_gnn = 0.4, you might do:
w
f
i
n
a
l
′
=
clamp
(
(
1
−
0.4
)
∗
w
f
i
n
a
l
+
0.4
∗
w
g
n
n
,
 
0
,
 
1
)
w 
final
′
​
 =clamp((1−0.4)∗w 
final
​
 +0.4∗w 
gnn
​
 , 0, 1)
This means if an edge already has some evidence (w_final from Hebbian), it will still dominate (60% weight) but the GNN can boost it 40%. If an edge has no evidence (w_final was zero and only w_gnn provides a value), then the final becomes essentially 40% of the GNN suggestion (which might be small but non-zero instead of staying at 0). We clamp again to ensure bounds.
f. Schedule Weekly: This job might be heavier (training a model), so we plan to run it weekly. For example, every weekend or once a week at low-traffic hours. If enable_gnn is false or if the model is not yet validated, we can skip or disable this without affecting the rest of the system.
Outcome of Task 2: A set of w_gnn values for edges (especially ones that lacked evidence) and updated w_final weights that incorporate these priors. This will help the simulator by suggesting transitions between techniques that logically should occur, even if not yet seen in the data (cold-start problem mitigation).
3. Simulator Integration
Modify the attack simulation logic to take advantage of the new weighted edges. The primary area of change is the AttackSimulator._get_next_techniques (or equivalent function) that chooses the next technique given the current one:
a. Prefer w_final for Next-Step Selection: When the simulator is determining which technique to simulate next, and it has a current technique X, it will look at outgoing :NEXT edges from X. If those edges have a w_final value (which they should if the plasticity job has run at least once), use w_final as the probability weight for selecting among them. Essentially, treat w_final as the learned transition probability (or proportional to it). If w_final sums to less than 1 or if some missing edges exist, the simulator could normalize the weights or combine with other sources.
b. Fallback to Historical Averages: In cases where for a given technique X, no w_final weights are present (e.g., brand new technique not seen in any flow and no GNN prior because GNN disabled or it also had no basis to connect it), the simulator should fallback to the original behavior. Originally, it might have used an average probability n.p from historical data or a uniform random choice. We will retain that as a safety net. The integration should be done such that if w_final exists and is non-zero, use it; otherwise use n.p or a default.
c. No Regression in Behavior: We need to ensure that this change does not break existing simulation logic. With identical data, using w_final should yield similar or better results than using the average probabilities. A part of this task is testing and calibrating to ensure that if our weights are off (say early in deployment, when not much data has been accumulated), the simulator still behaves reasonably. We might implement a threshold or confidence check: e.g., if an edge’s w_hebb is below some threshold and there's very limited data, perhaps rely more on historical probability until enough evidence accumulates. However, the consolidation floor and blending of long-term memory should cover this by never letting w_final stray too far if there's at least some long history.
d. Incorporate Cold-Start Edges: If the GNN prior or tactic bonus created some edges that had no historical data, the simulator will now have more options to choose next techniques from. This should be beneficial (the simulator won't get stuck because it thinks there are no paths). However, we should be cautious if the GNN suggests many possible edges – possibly treat those with lower weight unless evidence appears. This is more of a tuning consideration.
This integration will be done in the code, and unit tests or simulations will be run to confirm that:
Known sequences are still followed properly.
Noise in recent data doesn’t overly swing the simulation (stability improved by the blend).
The simulator can still proceed even if some edges are missing evidence (thanks to the imputed weights).
4. Flow Builder Integration
The flow builder (which presumably is responsible for generating or evaluating attack flows and their probabilities) will be adjusted to use the new weights:
a. Probability Calculation Adjustment: In the function (e.g., _calculate_probability) that computes the probability of an entire attack path or the next step probability, incorporate w_final if available. For example, if the flow builder previously multiplied probabilities of each step using historical transition probabilities, now it can use w_final for those transitions. If a :NEXT edge from technique A to B has w_final = 0.8 (indicating a strong supported transition), whereas historically it might have been 0.5, the flow builder can boost the overall flow probability accordingly (or vice versa, reduce if w_final is lower than historical).
b. Boosting Logic: If we do not want to fully replace the probability (especially if we suspect w_final might be overestimating some transitions early on), another approach is to use w_final as a multiplier or additive boost to the base probability. For instance, effective_prob = base_prob + k * (w_final - base_prob) where k is some confidence factor (if k=1, it replaces base_prob entirely with w_final; if k=0.5, it moves halfway towards w_final). However, given the goal is to rely on w_final primarily, we will likely just use w_final as the probability when present, under the assumption that it’s more accurate due to being evidence-weighted.
c. High w_final Shortcut: If w_final is very high for certain transitions, the flow builder might even choose to prioritize those in generating example flows or when multiple branches are possible, it can prefer the branch with higher weight. This isn’t a separate implementation task per se, but a natural outcome: by using w_final as probabilities, flows with high-weight transitions will bubble up as more probable.
No changes are needed for flows when weights don't exist; it will behave as before. This integration ensures consistency between how the simulator picks next steps and how probabilities are assigned to flows.
5. Weight Inspection API Endpoints
Implement two new API endpoints (read-only) to expose the relationship weights for analytics and debugging:
a. GET /v1/analytics/weights/next/{technique_id}: Given a technique (by ID or some identifier), return the top N successor techniques that have a :NEXT relationship from the given technique. The response will include each target technique and the weights, e.g.:
{
  "technique_id": "T1234",
  "next": [
     { "target": "T5678", "w_final": 0.62, "w_hebb": 0.50, "w_recent": 0.40, "w_long": 0.30, "w_imputed": 0.15 },
     { "target": "T9012", "w_final": 0.47, "w_hebb": 0.47, "w_recent": 0.60, "w_long": 0.20, "w_imputed": 0.0 },
     ...
  ]
}
The above is an example JSON structure (the exact format can be refined). It shows the top successors sorted by w_final. The components are included for transparency (so that an engineer or user can see how the final weight was composed from evidence and priors). We will likely cap the results (e.g. top 10 or 20 techniques) for performance and clarity. The endpoint should by default filter out any revoked techniques in the results, unless a query param like ?include_revoked=true is provided.
b. GET /v1/analytics/weights/cooccurs/{technique_id}: Similarly, for co-occurrence edges. Given a technique, return the top co-occurring techniques (unordered pairs). The structure would be similar, but since co-occurrence is symmetric, it could just list technique IDs that co-occur and the weights. This helps to see which techniques tend to appear in the same episodes as the given one.
c. Performance Considerations: These endpoints will query the graph database (Neo4j). We should create indexes or use efficient querying by technique_id to relationship. For example, MATCH (a:AttackPattern {id:$technique_id})- [r:NEXT]->(b:AttackPattern) RETURN b.id, r.w_final, r.w_hebb, ... ORDER BY r.w_final DESC LIMIT 20. Similar for CO_OCCURS but considering both directions (or storing it undirected and querying both). We expect these to be fast; our goal is under 200ms response for typical requests (95th percentile). Caching could be an option if needed, but since data updates nightly, a simple query might suffice.
d. Security/Read-Only: Mark these endpoints as read-only analytics. They don’t modify anything and can be exposed with appropriate auth. They are mainly for internal use (UI or analysis by experts) rather than public consumption.
Implementing these endpoints involves writing the controller/handler logic, the queries, and serializing the output. Also include these in documentation for how to use them.
6. Testing Plan
Alongside development, a comprehensive test suite will be created:
a. Unit Tests for Update Logic: Create unit tests for the core functions that compute weight updates. For example:
Test the EMA update calculation: given an initial w_recent and a new signal, ensure the new w_recent matches (1-α_r)*old + α_r*signal. Same for w_long.
Test the blending: given some w_recent and w_long, ensure w_hebb = m*w_recent + (1-m)*w_long.
Test the consolidation floor: if w_hebb would go below the floor with a decay, ensure the code enforces the minimum.
Test the defense reduction calculation: e.g., if dcount = 0, reduction = 0; if dcount = 1, reduction = 0.15 (or cap if >5 counters).
Test the tactic bonus logic: same tactic yields 0.08, unrelated yields baseline, etc.
Test the clamping: if computed weight goes above 1 or below 0, ensure it is clamped.
b. Integration Tests (Graph DB/Neo4j): Using a test Neo4j database (or a mocked layer), simulate a small number of episodes and actions:
Insert a few AttackPattern nodes and episodes with known co-occurrences and sequences.
Run the plasticity job logic (perhaps by calling the Cypher queries or a function that wraps them).
Query the resulting edges and verify that properties have been set as expected. For example, if two techniques co-occurred in one episode, check that a CO_OCCURS relationship exists with w_recent ≈ α_r, w_long ≈ α_l, w_hebb ≈ blend etc.
Verify the floor: if after one event w_hebb would be below 0.05, it should actually be 0.05.
Add a D3fendTechnique that counters one of the techniques and run the job again; verify that w_final on an edge involving that technique is reduced appropriately.
Mark a technique as revoked in the dataset and ensure that running the job does not produce edges involving it (unless we override a setting).
Test the GNN integration on a very small graph if possible (this might be more of a unit test by stubbing a model output rather than training an actual model in test).
c. Simulator Behavior Tests: Mock or run the Attack Simulator with a controlled set of data:
Case 1: When w_final exists for transitions, ensure the simulator picks the highest-weight transition most often (if stochastic) or exclusively (if deterministic), as expected.
Case 2: If w_final suggests a different path than historical average, check that the simulator follows the w_final. For instance, if historically A->B and A->C were equally likely, but now w_final(A->B) > w_final(A->C), the next technique chosen should reflect that bias.
Case 3: If w_final is not present, ensure it falls back to the old method without error.
Also test that overall flow probabilities computed by flow builder are consistent with the weights.
d. API Tests: Write tests for the weight inspection endpoints:
Call the endpoint for a technique in a test database and verify the response contains expected top neighbors with correct weights.
Test with a technique that has no edges (should return empty list or appropriate response).
Test that the performance is acceptable (maybe simulate many edges and measure query time, or at least ensure queries use indexes).
Security test: ensure that no modification is possible via these endpoints and that only allowed fields are returned.
These tests will be run in CI. Additionally, we might do a manual QA with a larger dataset to ensure the job scales and the outputs make sense (e.g., run the job on a snapshot of real data and have a domain expert verify some of the top connections intuitively match known attack flows).
7. Operational and Deployment Considerations
a. One-off Migration: Before enabling the nightly job in production, we need to backfill existing data:
Create :CO_OCCURS edges for all past episodes (so the system isn't starting from scratch). A one-time script will iterate through all existing AttackEpisode nodes, build the technique pairs, and MERGE the CO_OCCURS relationships with initial weights (0 or maybe we could even seed w_long proportional to historical co-occurrence counts if we want a head start).
Backfill the :NEXT edges as well: for all AttackAction sequences in stored flows, MERGE the corresponding AttackPattern NEXT edges. If historical probabilities exist for transitions, we could initialize w_long to that average and w_recent to that as well (or just leave at 0 and let the first nightly job compute it). For simplicity, we might set initial w_recent = w_long = 0 and allow the job to accumulate from scratch using all data – since it might process all episodes anyway on first run.
b. Enabling the Jobs: Configure the nightly job (and weekly job) in the scheduling system (e.g., a cronjob or a scheduled cloud function). Ensure that the jobs have appropriate resource allocation, as the nightly job needs to handle potentially up to 100k actions/10k episodes in under 5 minutes. We might batch updates in the queries or use streaming approaches if needed to avoid memory issues in the database.
c. Metrics and Monitoring: Instrument the job to log and emit metrics:
Count of edges updated (e.g., number of CO_OCCURS edges touched, number of NEXT edges touched).
Average or distribution of w_final values (to track if weights are trending to 0 or 1 too often).
Defense reduction stats: how many edges had reductions, average reduction amount.
Job duration in milliseconds.
For the GNN job, whether it ran and how many edges got a prior (and how long the training took).
These metrics can be sent to a monitoring dashboard or logs for analysis. This will help in tuning parameters if, say, we notice all weights saturate at the floor or something.
d. Logging: The job should log key actions with a trace ID so that if an issue in simulation is found, we can trace back what the weights were. For example, log the number of new edges created vs updated, and maybe sample a couple of edges with their before/after weights for sanity check (at debug level). Ensure logs are not too verbose to avoid clutter.
e. Rollback Plan: The changes we are making are mostly additive. We are not removing the old probability data; we are adding new weight properties and new code paths that use them. Therefore, rollback is straightforward:
If something goes wrong with the weight calculations or they seem to harm the simulation, we can disable the nightly job (stop it from running) and set the system to ignore w_final. The Attack Simulator and Flow Builder will then naturally fall back to using historical averages as they did before (we will keep that fallback logic permanently as a safety).
The presence of w_final on some edges does not harm anything if unused. We could even leave the computed weights in the database while disabling their usage.
Feature flags: plasticity.enable_gnn can be turned off to disable using the GNN blending at any time. We could also have a master flag like plasticity.enabled that if false, the simulator simply never looks at w_final even if present.
Because we do not remove or modify existing fields (only add new ones), the system can be rolled back by code/config changes without needing a complex data migration rollback. The relationships can remain – or if needed, we could write a script to remove the w_* properties or relationships, but that likely isn’t necessary.
f. Documentation & Knowledge Transfer: As part of deployment, ensure the team is aware of this new mechanism. Provide a runbook entry on how to re-run the job manually if needed, how to interpret the metrics, and how to turn off the feature if emergencies arise. Also, include instructions on extending this model (for example, if a new tactic is added or if we later incorporate external data into weights).
Deliverables
By the end of the 2-week period, the following deliverables are expected:
Plasticity Job Module: A new module or script (e.g., scripts/plasticity_run.py or a Neo4j stored procedure) that contains the logic for the nightly weight update job. This should be configurable (via the settings above) and include a CLI or scheduled entry point. Example configuration and cron schedule will be provided (so ops can deploy it to run nightly).
(Optional) GNN Job Module: If implemented in this sprint, a script or notebook for the GNN training and inference, integrated into a weekly scheduled job. If not fully productionized, at least a proof-of-concept in code that can be run on demand to generate w_gnn values.
Simulator Update: Changes in the AttackSimulator class (or relevant part of the codebase) to use w_final for next technique selection, with appropriate fallbacks.
Flow Builder Update: Changes in the flow probability calculation to incorporate the new weights.
API Endpoints: Two new read-only endpoints (/v1/analytics/weights/next/{id} and /v1/analytics/weights/cooccurs/{id}) implemented, documented, and tested.
Test Suite: New tests covering the functionality (unit tests for the math, integration tests for the job on sample data, and endpoint tests). These tests should be passing in CI.
Documentation: A document (e.g., docs/SPRINT6_PLASTICITY.md) explaining how the plasticity system works, how to configure it, and summarizing the approach. This should include at least the high-level description, config options, and maybe examples of Cypher queries used. It can draw from the content of this execution plan for consistency.
Example Cypher Snippets: Included either in the codebase or docs, showing how to do common queries related to these weights (for developers or for support debugging). For instance, how to query the top edges for a technique, how to find if any weight is below floor (shouldn’t happen if working), etc., largely for verification and maintenance.
Timeline and Milestones
Below is a suggested timeline for the 2-week sprint, breaking down the tasks into daily goals. (Adjustments can be made based on team velocity, but this provides a trackable plan.) Week 1:
Day 1-2: Finalize the data model changes and job scaffolding.
Add the new relationship properties (w_hebb, w_recent, etc.) in the data model definitions.
Write initial Cypher queries or pseudo-code for updating CO_OCCURS and NEXT edges. Test these queries on a small sample graph to ensure they do what is expected (e.g., run on a dev Neo4j with a couple of episodes).
Set up the skeleton for the nightly job in code (perhaps a Python script using a Neo4j driver or an APOC script).
Verify that merging relationships and setting properties works without performance issues on small scale.
Day 3-4: Implement integration with Simulator and Flow Builder, and draft API endpoints.
Modify the simulator code to use w_final. Test the simulator manually or with unit tests using dummy data to confirm it picks up weights.
Modify the flow builder calculation for probabilities.
Implement the two API endpoints (without full optimization yet). Make sure they return the expected data from a test instance.
By end of Day 4, basic end-to-end functionality is in place: one can run the job on sample data, then call the API and see weights, and run the simulator to see it using those weights.
Day 5-6: Focus on testing, refinement, and performance tuning.
Write the unit tests for the math logic and ensure all pass.
Run an integration test of the job on a dataset of, say, a few hundred episodes to gauge performance. Profile query times, and add indexes if needed (e.g., index on AttackPattern.stix_id if not already).
Tune parameters if initial tests show issues (e.g., if consolidation_floor is too high or low, adjust; if recent_alpha should be tweaked for stability).
Ensure the job completes quickly on the tested dataset. If any query is slow, consider splitting it or using periodic commit.
Finalize API output format and test with front-end or a colleague for feedback (make sure it’s usable).
By end of Week 1, we should have a solid implementation for the Hebbian update path and all critical integration points, with tests and basic docs done for those.
Week 2:
Day 7-8: (Optional Stretch) Implement and experiment with the GNN prior.
If proceeding, use these days to build the GraphSAGE model on a sample of the graph. Possibly use an existing library to expedite.
Train on available data (if using real data, perhaps run on a smaller subset or off-hours data export).
Evaluate whether the GNN predictions make sense (spot-check some high-prediction edges to see if they align with domain intuition).
Integrate the blending of w_gnn into the job (behind the enable_gnn flag).
If this is too time-consuming or risky to finish, decide whether to defer it. Even if deferred, ensure the infrastructure (like storing w_gnn property and having the flag) is in place so it can be added later seamlessly.
Day 9-10: Documentation, final adjustments, and QA.
Write and polish the documentation (SPRINT6_PLASTICITY.md) explaining how everything works. Include examples and perhaps figures if useful (e.g., a diagram of how weights flow or how two techniques connect).
Conduct a thorough QA: run the nightly job on a full set of test data that mimics production scale (if possible). Verify the performance criteria (should finish < 5 minutes). Verify memory or transaction log is not an issue in Neo4j.
Check the simulator on some corner cases (for example, an episode where a technique has no next technique with weight – does it handle properly?).
Ensure all tests are passing and add any new tests for things discovered.
If GNN was implemented, verify that running it doesn’t blow up the timeline (maybe it’s fine if training is say 30 minutes offline – since it’s weekly, but just note it).
Prepare release notes and communicate to the team that the feature is ready for release.
Throughout the timeline, adjust as necessary if some tasks take longer; for example, if the job performance needs extra optimization, that might cut into the optional GNN work (which is acceptable to defer). The timeline is a guideline to keep the work on track for the two-week window.
Expected Outcomes and Benefits
By following this plan, we expect to achieve the following outcomes:
Evidence-Preserving Technique Links: The relationships between attack techniques will now encode both short-term and long-term evidence of association. This means the system "remembers" historical co-occurrences and sequences while still adapting to new data. Edges won’t be overly skewed by just the most recent activity (mitigating recency bias), thanks to the dual timescale (recent vs. long) blending.
Stability in Simulation: The Attack Simulator will produce more stable and realistic attack paths. When a particular sequence has been observed consistently (even if not in the very latest data), the simulator will still consider it due to the retained long-term weight. Conversely, one-off spurious sequences will decay over time and not linger indefinitely. Overall, the simulation should be less jittery from day to day and more aligned with true probabilities.
Intelligent Handling of Sparse Data: For techniques that are new or rarely seen (isolated nodes in the graph), the system will not leave them completely disconnected. The tactic-based imputed weight gives a small nudge to connect techniques that should be related (e.g., an Initial Access technique often followed by Execution techniques will get a base weight). If enabled, the GNN prior further enhances this by using graph learning to suggest likely connections based on learned patterns in the data. This means the simulator can still explore plausible attack paths involving those techniques, providing better coverage.
Defense-Aware Probabilities: By incorporating D3FEND countermeasure knowledge, any attack techniques that are well-defended will have a lower weight to succeeding techniques. This effectively biases the simulation to either avoid or de-emphasize sequences that run into strong defenses, or at least mark them as less likely. This can lead to more realistic outputs or help highlight where an attack path might fail due to defenses (useful for analysis).
Observability and Debugging: The introduction of weight inspection APIs and logging means we have greater visibility into why the simulator is choosing certain paths. Stakeholders can query a technique and see “What are the most likely next steps according to our model?” and get an explanation in terms of evidence. This transparency will help in validating the model and building trust, as well as diagnosing if something seems off (we can see if maybe a weight is unexpectedly high or low and trace back the cause).
Performance within Limits: The design and queries are intended to be efficient. Using Neo4j’s ability to do set-based operations and merges, the nightly job should scale to large numbers of episodes. By focusing on top connections in APIs, we avoid transferring huge amounts of data unnecessarily. The expectation (per acceptance criteria) is that the nightly job handles on the order of 100k actions across 10k episodes in a few minutes, which seems feasible with proper indexing and moderate hardware. The weekly GNN job, if used, is heavier but infrequent; it’s effectively doing an offline training that can be managed separately.
In summary, this execution plan lays out a comprehensive approach to enhance the simulation engine with biologically-inspired Hebbian learning mechanisms and modern graph ML techniques, all while ensuring the solution is trackable, testable, and tunable. Following this plan will result in a more adaptive and robust attack technique graph that improves the fidelity of simulations and analyses going forward.



Sources
You said:
Ok now lets create a cohesive, cogent plan for execution.
ChatGPT said:
Here’s a cohesive, cogent execution plan distilled from the detailed breakdown you provided. It’s structured as a single sprint plan so it reads cleanly, is trackable, and emphasizes milestones, responsibilities, and outcomes.

Execution Plan: Hebbian Edge Weighting & Plasticity
Summary
We will implement neuroplasticity-inspired edge weighting in the Attack Technique graph to improve simulation stability and reduce recency bias. The solution blends Hebbian updates, decay, consolidation floors, tactic-based priors, defense-based reductions, and optional GNN priors into final edge weights (w_final) consumed by the simulator and flow builder.

Duration: 2 weeks (Sprint 6)
Outcome: Evidence-weighted technique edges with transparent observability and simulator integration.

Goals
Compute stable edge weights for :NEXT and :CO_OCCURS relationships using Hebbian learning.

Blend short-term vs. long-term evidence to resist recency bias.

Integrate tactic bonuses and defense reductions into final edge weights.

Provide read-only APIs for weight inspection and monitoring.

Ensure Attack Simulator and Flow Builder prefer w_final for decision-making.

(Optional) Incorporate GNN priors for sparse/isolated techniques.

Non-Goals
Full temporal KGE or continual retraining pipelines.

Advanced UI visualization (beyond basic inspection).

Changes to ingestion or upstream ATT&CK/D3FEND schemas.

Deliverables
Plasticity Job: nightly updater (scripts/plasticity_run.py + cron)

Simulator Integration: _get_next_techniques uses w_final

Flow Builder Integration: _calculate_probability uses w_final

APIs:

GET /v1/analytics/weights/next/{technique_id}

GET /v1/analytics/weights/cooccurs/{technique_id}

Test Suite: unit + integration + API tests

Docs: docs/SPRINT6_PLASTICITY.md (overview, configs, Cypher snippets)

Timeline & Milestones
Week 1
Day 1–2: Data Model & Job Scaffolding

Add weight properties to NEXT and CO_OCCURS edges.

Prototype Cypher for Hebbian updates & consolidation floor.

Backfill edges in dev environment.

Day 3–4: Simulator, Flow Builder, APIs

Update Simulator to use `w_fin_




No file chosenNo file chosen
ChatGPT can make mistakes. Check important info.

Edge Weighting and Plasticity (Hebbian + GNN Priors) – Execution Plan
Goal and Overview
This project is estimated to take 2 weeks. Its goal is to produce stable, evidence-weighted edges between attack techniques (nodes) that resist recency bias and improve simulation accuracy. We will achieve this by applying a Hebbian-style plasticity update with slow decay, a consolidation floor, tactic-based adjustments, defense-based reductions, and optional graph neural network (GNN) priors. In essence, we want the connections between techniques to strengthen when they frequently co-occur or transition together (a Hebbian "fire together, wire together" approach
en.wikipedia.org
) and to decay slowly over time so that historical patterns are not forgotten. New or isolated techniques will receive estimated weights using similarity-based heuristics or GNN predictions to avoid cold starts. Key Objectives:
Maintain two types of relationships between techniques in the graph: sequential transitions (:NEXT edges) and co-occurrences (:CO_OCCURS edges). Each edge carries various weight components (Hebbian short-term and long-term memories, imputed/prior weight, final combined weight, etc.).
Implement a nightly “plasticity” job that updates these edge weights based on new observations (flows/episodes), applying Hebbian learning rules (increment on co-activation, exponential decay) and adjustments like consolidation floor, tactic proximity bonuses, and defense technique penalties.
Optionally implement a weekly GNN-based job that generates prior weights for edges (using a GraphSAGE model for link prediction
stellargraph.readthedocs.io
stellargraph.readthedocs.io
) to inform connections where data is sparse, and blend these priors into the final weight.
Update the Attack Simulator and Flow Builder components to consume the new w_final weights for deciding technique transitions and calculating probabilities, respectively.
Provide read-only API endpoints to inspect the computed weights (for observability and potential UI use).
Ensure the solution is performant (e.g. the nightly job runs within a few minutes on typical data volumes) and that it improves stability of simulations (less fluctuation due to recent data spikes) without regressing accuracy.
Scope
The scope of this execution plan includes the following components:
Edge Types and Properties: Introduction of two relationship types between AttackPattern nodes: NEXT (ordered edges representing observed sequential transitions) and CO_OCCURS (undirected co-occurrence relationships for techniques seen in the same episode). Each edge will store weight components: w_hebb (Hebbian blended weight), w_recent (recent EMA contribution), w_long (long-term contribution), w_imputed (imputed/prior weight from tactics or GNN), w_final (the final combined weight used by consumers), and updated_at (timestamp of last update). These properties will be maintained and updated by the jobs described below.
Batch Jobs: A nightly plasticity job will compute co-occurrence signals from the latest episodes/flows and update the CO_OCCURS and NEXT edges accordingly (applying Hebbian increment and decay to w_recent and w_long). It will then compute blended weights (w_hebb), apply consolidation floor minima, adjust for tactic proximity (w_imputed partial), apply any defense-based reductions, and finally set w_final for each edge. Additionally, a weekly GNN prior job is in scope (configurable, optional) which trains a lightweight GraphSAGE-based model to predict link probabilities for technique pairs; those predictions (w_gnn) can be blended into w_final for edges that have sparse direct evidence. Both jobs will exclude revoked or deprecated techniques by default (unless explicitly configured otherwise).
Consumers (Simulator & Flow Builder): The Attack Simulator will be modified to use the new edge weights. Specifically, when deciding the next technique in a simulated attack sequence, it will prefer the probability given by w_final on a :NEXT edge if available, rather than the historical average probability (n.p) used previously. The Flow Builder (which constructs attack flows and calculates step probabilities) will also incorporate w_final by boosting the probability of transitions that have a high learned weight. This ensures that the learned graph influences simulation behavior, making it more realistic and less random. If w_final is missing for a given transition (e.g. new techniques with no data and no imputed prior), the system will gracefully fall back to the historical averages to maintain continuity.
APIs for Observability: We will implement read-only API endpoints to expose the weights for inspection. These might include endpoints such as GET /v1/analytics/weights/next/{technique_id} to retrieve the top successor techniques (outgoing NEXT edges from a given technique) ranked by w_final (and possibly returning the components w_hebb, w_imputed, etc. for transparency), and GET /v1/analytics/weights/cooccurs/{technique_id} to retrieve top co-occurring techniques for a given technique. These endpoints will help in debugging, UI visualizations of the technique network, and verifying that the weight updates are intuitive. They will be optimized for performance (e.g., returning top 20 results within ~200ms at the 95th percentile).
Out of Scope (Non-Goals for this Sprint): To keep the effort focused, certain aspects are explicitly not included in this sprint:
Developing a full temporal knowledge graph embedding or complex ML pipeline beyond the lightweight GNN prior. (No large-scale training infrastructure or KGE retraining in production yet.)
Advanced UI visualizations of the technique graph beyond basic weight inspection outputs. (UI work will be minimal, relying on the API outputs; a more polished visualization can be tackled in a future sprint if needed.)
Any changes to how data is ingested or fundamental changes to underlying Attack/Defense models. (We assume input data like episodes and actions are available as usual; we are only enriching how we derive technique relationships from them.)
Data Model and Configuration
Relationship Properties: When creating new :NEXT or :CO_OCCURS relationships, the system will initialize all weight properties to default values. By default on creation:
w_hebb = 0.0 (Hebbian blended weight, initially zero)
w_recent = 0.0 (Exponential moving average for recent evidence, short timescale)
w_long = 0.0 (Long-term accumulated evidence, slower timescale)
w_imputed = 0.0 (Imputed weight from non-observational priors, e.g. tactic similarity or GNN)
w_final = 0.0 (Final weight used by consumers, will be calculated)
updated_at = timestamp() (record last update time for potential debugging or staleness checks)
These properties are stored on each relationship (NEXT or CO_OCCURS) between AttackPattern nodes. Configurable Parameters: The behavior of the plasticity updates and blending is governed by a set of configuration settings (with likely defaults as below):
plasticity.consolidation_floor = 0.05 – A minimum floor value for w_hebb once any evidence has been seen. This prevents weights from decaying back to near zero after having been established, ensuring a base level of "memory."
plasticity.recent_alpha = 0.3 – The alpha (learning rate) for the recent exponential moving average (EMA). This represents how strongly new evidence influences the short-term memory. For example, using α_r = 0.3 means each new observation contributes 30% to the recent weight (and 70% is retained from previous recent value).
plasticity.long_alpha = 0.01 – The alpha for the long-term EMA. This is a much smaller value, meaning the long-term memory accumulates very slowly and retains historical evidence for a long time (e.g., 1% update on new evidence).
plasticity.metaplastic_m = 0.6 – The blending factor (m) between recent and long-term weights when computing w_hebb. A higher m leans more on recent evidence, while (1-m) weights the long-term memory. Here 0.6 means 60% recent, 40% long-term in the blended Hebbian weight.
plasticity.tactic_bonus_same = 0.08 – Bonus weight to add in w_imputed if two techniques share the same tactic category. (Techniques in the same MITRE ATT&CK tactic are likely to co-occur or transition, so we boost them slightly.)
plasticity.tactic_bonus_adjacent = 0.05 – Bonus to add if tactics are adjacent or closely related in the framework (for example, one could define adjacency based on typical attack flow, e.g. an "Initial Access" technique followed by an "Execution" or "Persistence" might be considered adjacent tactics).
plasticity.defense_reduction_per_counter = 0.15 – Reduction factor per defending countermeasure present. For each defensive technique (from MITRE D3FEND) that counters either of the two attack techniques in an edge, we reduce weight by 0.15, up to a cap.
plasticity.defense_reduction_cap = 0.75 – Maximum total reduction from defenses. Even if there are many defensive measures, the weight reduction will not exceed 0.75 (i.e., we won't reduce the weight completely to zero from defenses alone; a minimum 25% of the weight remains to account for some residual possibility).
plasticity.enable_gnn = false – Feature flag to enable the Graph Neural Network prior integration. By default it may be off (especially if the GNN model is not yet trained or validated).
plasticity.alpha_gnn = 0.4 – Blending factor for GNN prior. If GNN is enabled, the final weight could be blended as w_final = (1-α_gnn)*w_final_hebbian + α_gnn*w_gnn. For example 0.4 means 40% of the GNN-predicted weight influences the final value (applied to edges that lack strong evidence).
These settings allow tuning the balance between recent vs. long-term learning, the impact of tactics and defenses, and the influence of the GNN model. They can be adjusted based on experimental results.
Implementation Plan and Tasks
Below is a breakdown of the tasks and components that need to be implemented or modified. Each major task is outlined with sub-tasks or steps for clarity:
1. Nightly Plasticity Update Job (Hebbian Learning & Decay)
Implement a batch job (to run nightly) that processes recent attack episodes and updates the weights on :NEXT and :CO_OCCURS edges accordingly. The job will perform the following steps for each relevant relationship:
a. Extract Co-occurrence Pairs: Go through each new or updated attack episode (or all episodes nightly, depending on volume) and gather all unique pairs of techniques that co-occur in the same episode. For each episode node that contains multiple AttackAction nodes (techniques executed in that episode), produce all unordered pairs of those techniques. This will be used to update :CO_OCCURS edges. Implementation detail: Use a Cypher query to collect technique IDs in an episode and then unwind pairs. Example snippet:
// Build or update CO_OCCURS edges from episodes
MATCH (e:AttackEpisode)
  WITH e
  MATCH (e)-[:CONTAINS]->(a:AttackAction)
  WITH e, collect(DISTINCT a.attack_pattern_ref) AS techs
  WHERE size(techs) >= 2
  UNWIND techs AS tA
  UNWIND techs AS tB
  WITH tA, tB WHERE tA < tB  // ensure each unordered pair is processed once
  MATCH (i:AttackPattern {stix_id: tA})
  MATCH (j:AttackPattern {stix_id: tB})
  MERGE (i)-[r:CO_OCCURS]->(j)
    ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0, r.updated_at = timestamp()
  WITH r
  // Hebbian increment (η) and decay (λ) for co-occurrence
  SET r.w_recent = (1 - $recent_alpha) * r.w_recent + $recent_alpha * 1.0    // incorporate this co-occurrence event
  SET r.w_long   = (1 - $long_alpha)   * r.w_long   + $long_alpha   * 1.0    // long-term accumulation
  WITH r, $metaplastic_m AS m
  SET r.w_hebb = m * r.w_recent + (1 - m) * r.w_long
  SET r.w_hebb = CASE WHEN r.w_hebb < $consolidation_floor THEN $consolidation_floor ELSE r.w_hebb END
  SET r.updated_at = timestamp();
In the above pseudo-code, $recent_alpha, $long_alpha, $metaplastic_m, and $consolidation_floor are parameters coming from configuration (e.g. 0.3, 0.01, 0.6, 0.05 respectively as per defaults). The logic:
If the CO_OCCURS relationship between two techniques is new, initialize weights to 0.
Increase the recent weight (w_recent) by α_r * 1.0 (since a co-occurrence is a binary event, we treat its "signal" as 1 for that pair in this episode) and decay the existing recent weight by (1-α_r).
Increase the long-term weight (w_long) by the very small α_l * 1.0 and decay the existing by (1-α_l).
Compute a blended Hebbian weight: w_hebb = m * w_recent + (1-m) * w_long. This metaplastic approach ensures that if there’s a sudden surge or drop in co-occurrence frequency, the w_recent will capture it quickly (because of higher α_r and heavier weight in blend), but w_long ensures the historical average still anchors the value.
Apply a consolidation floor: ensure w_hebb doesn’t drop below a certain floor (e.g. 0.05) once there has been at least some evidence. This means once an edge has been established (even modestly), it never “forgets” completely; it will decay only to this minimum level, not to zero.
Update the timestamp.
b. Update Sequential Transition Edges: Similarly, update :NEXT edges representing direct sequential transitions in observed attack flows. We will use the observed probabilities of transitions as the signal. For each AttackAction that has a :NEXT relationship to a subsequent AttackAction within the same flow, accumulate an average probability of that transition (if the data has an explicit probability or frequency). Then update or create a corresponding AttackPattern -[:NEXT]-> AttackPattern edge between the technique of the first action and the technique of the second action. The update to w_recent and w_long will be similar, but using the transition probability as the increment signal instead of a fixed 1.0. Implementation detail: Example Cypher snippet to update NEXT edges from observed action-to-action transitions:
MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
  WITH a1.attack_pattern_ref AS i, a2.attack_pattern_ref AS j,
       avg(coalesce(n.probability, n.p, 0.5)) AS s  // average observed transition probability (fallback 0.5 if not provided)
  MATCH (ti:AttackPattern {stix_id: i})
  MATCH (tj:AttackPattern {stix_id: j})
  MERGE (ti)-[r:NEXT]->(tj)
    ON CREATE SET r.w_hebb = 0.0, r.w_recent = 0.0, r.w_long = 0.0
  WITH r, s
  SET r.w_recent = (1 - $recent_alpha) * r.w_recent + $recent_alpha * s,
      r.w_long   = (1 - $long_alpha)   * r.w_long   + $long_alpha   * s,
      r.w_hebb   = $metaplastic_m * r.w_recent + (1 - $metaplastic_m) * r.w_long;
This will ensure w_recent and w_long for sequential edges capture transition likelihoods (with w_recent reacting to latest patterns and w_long maintaining a running background rate). We use a possibly slightly different long_alpha for transitions (in the snippet, 0.5% = 0.005 was used, assuming transitions might accumulate even more slowly).
c. Apply Tactic Proximity Bonus: After updating w_hebb via co-occurrence or sequential events, compute an imputed weight component w_imputed based on tactic similarity of the two techniques. If two techniques belong to the same MITRE ATT&CK tactic category, add a bonus (e.g. 0.08). If they are in tactics that are commonly adjacent in attack flows, add a smaller bonus (e.g. 0.05). For any other combination, a minimal default (perhaps 0.02 or 0) could be used if we want a slight base connectivity for completely unrelated tactics. This bonus helps connect techniques that logically belong together in an attack chain even if data is sparse.
d. Apply Defense-Based Reduction: For each edge, determine if either of the connected techniques has known defensive countermeasures in the D3FEND framework. If technique A or B is countered by one or more D3fendTechnique (defensive techniques), reduce the weight. For example, if there are dcount distinct defenses that counter A or B, we subtract min(dcount * 0.15, 0.75) from the weight (capped at 0.75). This models the idea that if an attack step has strong defenses, it should be less likely or effective in a simulated chain, thus lowering the edge weight.
e. Compute Final Weight: Combine the above components into the final edge weight. The formula will be roughly:
w
f
i
n
a
l
=
clamp
(
w
h
e
b
b
+
w
i
m
p
u
t
e
d
−
defense_reduction
,
 
0
,
 
1
)
w 
final
​
 =clamp(w 
hebb
​
 +w 
imputed
​
 −defense_reduction, 0, 1)
Ensure the final value is clamped between 0 and 1 (since these represent probabilities or normalized weights). So even after adding tactic bonuses or subtracting defense penalties, we keep within [0,1]. We can do the tactic bonus and defense penalty in one Cypher pass after computing w_hebb. For example:
// Compute tactic bonus and defense reduction, then final weight
MATCH (i:AttackPattern)-[:HAS_TACTIC]->(ti:Tactic),
      (j:AttackPattern)-[:HAS_TACTIC]->(tj:Tactic),
      (i)-[r:NEXT]->(j)
WITH r, ti.shortname AS t1, tj.shortname AS t2,
     CASE 
       WHEN t1 = t2 
         THEN $tactic_bonus_same                      // same tactic bonus
       WHEN (t1,t2) IN [(["initial-access","execution"], ["persistence","privilege-escalation"])] 
         THEN $tactic_bonus_adjacent                  // example adjacent tactics pair bonus
       ELSE 0.02 
     END AS tactic_bonus
// Now account for defenses countering either technique
MATCH (i)<-[:COUNTERS]-(d1:D3fendTechnique)
MATCH (j)<-[:COUNTERS]-(d2:D3fendTechnique)
WITH r, tactic_bonus, count(DISTINCT d1) + count(DISTINCT d2) AS dcount
SET r.w_imputed = tactic_bonus
SET r.w_final = apoc.number.clamp(
                  r.w_hebb + r.w_imputed - least(dcount * $defense_reduction_per_counter, $defense_reduction_cap),
                  0, 1
                );
In the above pseudo-code, we calculate a tactic_bonus based on whether tactics are identical or in a defined adjacent set. We then count defensive techniques (d1, d2) that counter each side. We set w_imputed to the tactic bonus (note: if we later incorporate embedding similarity or GNN, that would also contribute to w_imputed). Finally, set w_final as w_hebb + w_imputed - defense_penalty, capped between 0 and 1. The apoc.number.clamp and least() (if using APOC library) handle the clamping and capping logic.
f. Exclude Revoked/Deprecated Techniques: The job will by default ignore any AttackPattern that is marked as revoked or deprecated in the MITRE ATT&CK data. This means we won't create or update edges involving those nodes, unless a configuration flag indicates to include them. This ensures our graph of techniques remains clean and focused on active techniques. (Internally, the Cypher queries might include a condition like WHERE NOT i.revoked AND NOT j.revoked etc., if such properties exist on the nodes.)
g. Scheduling and Idempotence: The nightly job should be idempotent (running it twice on the same data should yield the same weights). It should process new data since the last run. We may implement it to scan all episodes or only recent ones; if scanning all, the EMA update inherently gives less weight to older events due to decay factors. We will schedule this job to run during off-hours (e.g., every night at midnight UTC) via a cron or background worker.
Outcome of Task 1: After this job runs, the graph will have updated weights: both CO_OCCURS and NEXT edges reflecting recent learning while not forgetting past patterns. The w_final is fully computed for all edges that have any evidence or imputed values. These weights are ready to be used by the simulator and exposed via APIs.
2. Weekly GNN Prior Job (Optional)
This task involves training and applying a Graph Neural Network model (e.g., GraphSAGE) to predict the likelihood of edges between techniques, serving as a prior for edges with little or no direct evidence. This is considered optional and might be implemented if time permits or enabled later, but we outline it for completeness:
a. Graph Data Preparation: Construct a training dataset using the current technique graph. Use existing :NEXT and :CO_OCCURS edges with high w_hebb or known occurrences as positive examples (these represent technique pairs that do occur together or in sequence). For negative examples, sample pairs of techniques that are not connected by an edge (or have very low weight). Ensure a balanced or reasonable ratio of positive to negative samples.
b. Feature Engineering: Determine what features to use for the GNN. Likely features include:
Node features: could use technique text embeddings (e.g., vector representations of the technique description or name), one-hot encodings of tactic categories, flags for platforms or tags, node degree or historical frequency.
Possibly edge features: but GraphSAGE typically learns node embeddings which we combine for link prediction. We might rely on the model to learn from node neighborhoods.
c. Train GraphSAGE Link Predictor: Use a framework (such as DGL or StellarGraph) to train a GraphSAGE model to output a probability that a link exists between two nodes
stellargraph.readthedocs.io
. This usually involves:
Generating node embeddings via GraphSAGE by sampling neighbor nodes (the graph of techniques and their connections is used as the structure for GraphSAGE).
Applying a link prediction layer (e.g., take two node embeddings and apply a binary operator like concatenation or dot product, then a sigmoid to get probability).
Train with a binary cross-entropy loss on the positive vs negative edges.
The model will learn patterns of the graph, potentially generalizing to suggest new connections (e.g., it might learn that techniques under the same tactic or with similar semantic meaning should have a higher link probability, even if our Hebbian job hasn't seen them together yet).
d. Generate w_gnn Predictions: After training (which can be done offline or as part of the weekly job), use the GNN model to infer scores for candidate edges. Focus on sparse or isolated techniques – for example, pairs of techniques that share a tactic or have similar features but currently have no w_hebb evidence. The model will output a probability (or score between 0 and 1) for those pairs. Store these as w_gnn on the corresponding edges (creating the edge if it doesn’t exist in the graph already). This essentially is a way to fill in the graph with plausible connections that haven’t been observed yet.
e. Blend GNN Prior into Final Weight: If plasticity.enable_gnn is true, then update the w_final for relevant edges by blending the existing w_final (from Hebbian calculation) with the GNN prediction. For example, if alpha_gnn = 0.4, you might do:
w
f
i
n
a
l
′
=
clamp
(
(
1
−
0.4
)
∗
w
f
i
n
a
l
+
0.4
∗
w
g
n
n
,
 
0
,
 
1
)
w 
final
′
​
 =clamp((1−0.4)∗w 
final
​
 +0.4∗w 
gnn
​
 , 0, 1)
This means if an edge already has some evidence (w_final from Hebbian), it will still dominate (60% weight) but the GNN can boost it 40%. If an edge has no evidence (w_final was zero and only w_gnn provides a value), then the final becomes essentially 40% of the GNN suggestion (which might be small but non-zero instead of staying at 0). We clamp again to ensure bounds.
f. Schedule Weekly: This job might be heavier (training a model), so we plan to run it weekly. For example, every weekend or once a week at low-traffic hours. If enable_gnn is false or if the model is not yet validated, we can skip or disable this without affecting the rest of the system.
Outcome of Task 2: A set of w_gnn values for edges (especially ones that lacked evidence) and updated w_final weights that incorporate these priors. This will help the simulator by suggesting transitions between techniques that logically should occur, even if not yet seen in the data (cold-start problem mitigation).
3. Simulator Integration
Modify the attack simulation logic to take advantage of the new weighted edges. The primary area of change is the AttackSimulator._get_next_techniques (or equivalent function) that chooses the next technique given the current one:
a. Prefer w_final for Next-Step Selection: When the simulator is determining which technique to simulate next, and it has a current technique X, it will look at outgoing :NEXT edges from X. If those edges have a w_final value (which they should if the plasticity job has run at least once), use w_final as the probability weight for selecting among them. Essentially, treat w_final as the learned transition probability (or proportional to it). If w_final sums to less than 1 or if some missing edges exist, the simulator could normalize the weights or combine with other sources.
b. Fallback to Historical Averages: In cases where for a given technique X, no w_final weights are present (e.g., brand new technique not seen in any flow and no GNN prior because GNN disabled or it also had no basis to connect it), the simulator should fallback to the original behavior. Originally, it might have used an average probability n.p from historical data or a uniform random choice. We will retain that as a safety net. The integration should be done such that if w_final exists and is non-zero, use it; otherwise use n.p or a default.
c. No Regression in Behavior: We need to ensure that this change does not break existing simulation logic. With identical data, using w_final should yield similar or better results than using the average probabilities. A part of this task is testing and calibrating to ensure that if our weights are off (say early in deployment, when not much data has been accumulated), the simulator still behaves reasonably. We might implement a threshold or confidence check: e.g., if an edge’s w_hebb is below some threshold and there's very limited data, perhaps rely more on historical probability until enough evidence accumulates. However, the consolidation floor and blending of long-term memory should cover this by never letting w_final stray too far if there's at least some long history.
d. Incorporate Cold-Start Edges: If the GNN prior or tactic bonus created some edges that had no historical data, the simulator will now have more options to choose next techniques from. This should be beneficial (the simulator won't get stuck because it thinks there are no paths). However, we should be cautious if the GNN suggests many possible edges – possibly treat those with lower weight unless evidence appears. This is more of a tuning consideration.
This integration will be done in the code, and unit tests or simulations will be run to confirm that:
Known sequences are still followed properly.
Noise in recent data doesn’t overly swing the simulation (stability improved by the blend).
The simulator can still proceed even if some edges are missing evidence (thanks to the imputed weights).
4. Flow Builder Integration
The flow builder (which presumably is responsible for generating or evaluating attack flows and their probabilities) will be adjusted to use the new weights:
a. Probability Calculation Adjustment: In the function (e.g., _calculate_probability) that computes the probability of an entire attack path or the next step probability, incorporate w_final if available. For example, if the flow builder previously multiplied probabilities of each step using historical transition probabilities, now it can use w_final for those transitions. If a :NEXT edge from technique A to B has w_final = 0.8 (indicating a strong supported transition), whereas historically it might have been 0.5, the flow builder can boost the overall flow probability accordingly (or vice versa, reduce if w_final is lower than historical).
b. Boosting Logic: If we do not want to fully replace the probability (especially if we suspect w_final might be overestimating some transitions early on), another approach is to use w_final as a multiplier or additive boost to the base probability. For instance, effective_prob = base_prob + k * (w_final - base_prob) where k is some confidence factor (if k=1, it replaces base_prob entirely with w_final; if k=0.5, it moves halfway towards w_final). However, given the goal is to rely on w_final primarily, we will likely just use w_final as the probability when present, under the assumption that it’s more accurate due to being evidence-weighted.
c. High w_final Shortcut: If w_final is very high for certain transitions, the flow builder might even choose to prioritize those in generating example flows or when multiple branches are possible, it can prefer the branch with higher weight. This isn’t a separate implementation task per se, but a natural outcome: by using w_final as probabilities, flows with high-weight transitions will bubble up as more probable.
No changes are needed for flows when weights don't exist; it will behave as before. This integration ensures consistency between how the simulator picks next steps and how probabilities are assigned to flows.
5. Weight Inspection API Endpoints
Implement two new API endpoints (read-only) to expose the relationship weights for analytics and debugging:
a. GET /v1/analytics/weights/next/{technique_id}: Given a technique (by ID or some identifier), return the top N successor techniques that have a :NEXT relationship from the given technique. The response will include each target technique and the weights, e.g.:
{
  "technique_id": "T1234",
  "next": [
     { "target": "T5678", "w_final": 0.62, "w_hebb": 0.50, "w_recent": 0.40, "w_long": 0.30, "w_imputed": 0.15 },
     { "target": "T9012", "w_final": 0.47, "w_hebb": 0.47, "w_recent": 0.60, "w_long": 0.20, "w_imputed": 0.0 },
     ...
  ]
}
The above is an example JSON structure (the exact format can be refined). It shows the top successors sorted by w_final. The components are included for transparency (so that an engineer or user can see how the final weight was composed from evidence and priors). We will likely cap the results (e.g. top 10 or 20 techniques) for performance and clarity. The endpoint should by default filter out any revoked techniques in the results, unless a query param like ?include_revoked=true is provided.
b. GET /v1/analytics/weights/cooccurs/{technique_id}: Similarly, for co-occurrence edges. Given a technique, return the top co-occurring techniques (unordered pairs). The structure would be similar, but since co-occurrence is symmetric, it could just list technique IDs that co-occur and the weights. This helps to see which techniques tend to appear in the same episodes as the given one.
c. Performance Considerations: These endpoints will query the graph database (Neo4j). We should create indexes or use efficient querying by technique_id to relationship. For example, MATCH (a:AttackPattern {id:$technique_id})- [r:NEXT]->(b:AttackPattern) RETURN b.id, r.w_final, r.w_hebb, ... ORDER BY r.w_final DESC LIMIT 20. Similar for CO_OCCURS but considering both directions (or storing it undirected and querying both). We expect these to be fast; our goal is under 200ms response for typical requests (95th percentile). Caching could be an option if needed, but since data updates nightly, a simple query might suffice.
d. Security/Read-Only: Mark these endpoints as read-only analytics. They don’t modify anything and can be exposed with appropriate auth. They are mainly for internal use (UI or analysis by experts) rather than public consumption.
Implementing these endpoints involves writing the controller/handler logic, the queries, and serializing the output. Also include these in documentation for how to use them.
6. Testing Plan
Alongside development, a comprehensive test suite will be created:
a. Unit Tests for Update Logic: Create unit tests for the core functions that compute weight updates. For example:
Test the EMA update calculation: given an initial w_recent and a new signal, ensure the new w_recent matches (1-α_r)*old + α_r*signal. Same for w_long.
Test the blending: given some w_recent and w_long, ensure w_hebb = m*w_recent + (1-m)*w_long.
Test the consolidation floor: if w_hebb would go below the floor with a decay, ensure the code enforces the minimum.
Test the defense reduction calculation: e.g., if dcount = 0, reduction = 0; if dcount = 1, reduction = 0.15 (or cap if >5 counters).
Test the tactic bonus logic: same tactic yields 0.08, unrelated yields baseline, etc.
Test the clamping: if computed weight goes above 1 or below 0, ensure it is clamped.
b. Integration Tests (Graph DB/Neo4j): Using a test Neo4j database (or a mocked layer), simulate a small number of episodes and actions:
Insert a few AttackPattern nodes and episodes with known co-occurrences and sequences.
Run the plasticity job logic (perhaps by calling the Cypher queries or a function that wraps them).
Query the resulting edges and verify that properties have been set as expected. For example, if two techniques co-occurred in one episode, check that a CO_OCCURS relationship exists with w_recent ≈ α_r, w_long ≈ α_l, w_hebb ≈ blend etc.
Verify the floor: if after one event w_hebb would be below 0.05, it should actually be 0.05.
Add a D3fendTechnique that counters one of the techniques and run the job again; verify that w_final on an edge involving that technique is reduced appropriately.
Mark a technique as revoked in the dataset and ensure that running the job does not produce edges involving it (unless we override a setting).
Test the GNN integration on a very small graph if possible (this might be more of a unit test by stubbing a model output rather than training an actual model in test).
c. Simulator Behavior Tests: Mock or run the Attack Simulator with a controlled set of data:
Case 1: When w_final exists for transitions, ensure the simulator picks the highest-weight transition most often (if stochastic) or exclusively (if deterministic), as expected.
Case 2: If w_final suggests a different path than historical average, check that the simulator follows the w_final. For instance, if historically A->B and A->C were equally likely, but now w_final(A->B) > w_final(A->C), the next technique chosen should reflect that bias.
Case 3: If w_final is not present, ensure it falls back to the old method without error.
Also test that overall flow probabilities computed by flow builder are consistent with the weights.
d. API Tests: Write tests for the weight inspection endpoints:
Call the endpoint for a technique in a test database and verify the response contains expected top neighbors with correct weights.
Test with a technique that has no edges (should return empty list or appropriate response).
Test that the performance is acceptable (maybe simulate many edges and measure query time, or at least ensure queries use indexes).
Security test: ensure that no modification is possible via these endpoints and that only allowed fields are returned.
These tests will be run in CI. Additionally, we might do a manual QA with a larger dataset to ensure the job scales and the outputs make sense (e.g., run the job on a snapshot of real data and have a domain expert verify some of the top connections intuitively match known attack flows).
7. Operational and Deployment Considerations
a. One-off Migration: Before enabling the nightly job in production, we need to backfill existing data:
Create :CO_OCCURS edges for all past episodes (so the system isn't starting from scratch). A one-time script will iterate through all existing AttackEpisode nodes, build the technique pairs, and MERGE the CO_OCCURS relationships with initial weights (0 or maybe we could even seed w_long proportional to historical co-occurrence counts if we want a head start).
Backfill the :NEXT edges as well: for all AttackAction sequences in stored flows, MERGE the corresponding AttackPattern NEXT edges. If historical probabilities exist for transitions, we could initialize w_long to that average and w_recent to that as well (or just leave at 0 and let the first nightly job compute it). For simplicity, we might set initial w_recent = w_long = 0 and allow the job to accumulate from scratch using all data – since it might process all episodes anyway on first run.
b. Enabling the Jobs: Configure the nightly job (and weekly job) in the scheduling system (e.g., a cronjob or a scheduled cloud function). Ensure that the jobs have appropriate resource allocation, as the nightly job needs to handle potentially up to 100k actions/10k episodes in under 5 minutes. We might batch updates in the queries or use streaming approaches if needed to avoid memory issues in the database.
c. Metrics and Monitoring: Instrument the job to log and emit metrics:
Count of edges updated (e.g., number of CO_OCCURS edges touched, number of NEXT edges touched).
Average or distribution of w_final values (to track if weights are trending to 0 or 1 too often).
Defense reduction stats: how many edges had reductions, average reduction amount.
Job duration in milliseconds.
For the GNN job, whether it ran and how many edges got a prior (and how long the training took).
These metrics can be sent to a monitoring dashboard or logs for analysis. This will help in tuning parameters if, say, we notice all weights saturate at the floor or something.
d. Logging: The job should log key actions with a trace ID so that if an issue in simulation is found, we can trace back what the weights were. For example, log the number of new edges created vs updated, and maybe sample a couple of edges with their before/after weights for sanity check (at debug level). Ensure logs are not too verbose to avoid clutter.
e. Rollback Plan: The changes we are making are mostly additive. We are not removing the old probability data; we are adding new weight properties and new code paths that use them. Therefore, rollback is straightforward:
If something goes wrong with the weight calculations or they seem to harm the simulation, we can disable the nightly job (stop it from running) and set the system to ignore w_final. The Attack Simulator and Flow Builder will then naturally fall back to using historical averages as they did before (we will keep that fallback logic permanently as a safety).
The presence of w_final on some edges does not harm anything if unused. We could even leave the computed weights in the database while disabling their usage.
Feature flags: plasticity.enable_gnn can be turned off to disable using the GNN blending at any time. We could also have a master flag like plasticity.enabled that if false, the simulator simply never looks at w_final even if present.
Because we do not remove or modify existing fields (only add new ones), the system can be rolled back by code/config changes without needing a complex data migration rollback. The relationships can remain – or if needed, we could write a script to remove the w_* properties or relationships, but that likely isn’t necessary.
f. Documentation & Knowledge Transfer: As part of deployment, ensure the team is aware of this new mechanism. Provide a runbook entry on how to re-run the job manually if needed, how to interpret the metrics, and how to turn off the feature if emergencies arise. Also, include instructions on extending this model (for example, if a new tactic is added or if we later incorporate external data into weights).
Deliverables
By the end of the 2-week period, the following deliverables are expected:
Plasticity Job Module: A new module or script (e.g., scripts/plasticity_run.py or a Neo4j stored procedure) that contains the logic for the nightly weight update job. This should be configurable (via the settings above) and include a CLI or scheduled entry point. Example configuration and cron schedule will be provided (so ops can deploy it to run nightly).
(Optional) GNN Job Module: If implemented in this sprint, a script or notebook for the GNN training and inference, integrated into a weekly scheduled job. If not fully productionized, at least a proof-of-concept in code that can be run on demand to generate w_gnn values.
Simulator Update: Changes in the AttackSimulator class (or relevant part of the codebase) to use w_final for next technique selection, with appropriate fallbacks.
Flow Builder Update: Changes in the flow probability calculation to incorporate the new weights.
API Endpoints: Two new read-only endpoints (/v1/analytics/weights/next/{id} and /v1/analytics/weights/cooccurs/{id}) implemented, documented, and tested.
Test Suite: New tests covering the functionality (unit tests for the math, integration tests for the job on sample data, and endpoint tests). These tests should be passing in CI.
Documentation: A document (e.g., docs/SPRINT6_PLASTICITY.md) explaining how the plasticity system works, how to configure it, and summarizing the approach. This should include at least the high-level description, config options, and maybe examples of Cypher queries used. It can draw from the content of this execution plan for consistency.
Example Cypher Snippets: Included either in the codebase or docs, showing how to do common queries related to these weights (for developers or for support debugging). For instance, how to query the top edges for a technique, how to find if any weight is below floor (shouldn’t happen if working), etc., largely for verification and maintenance.
Timeline and Milestones
Below is a suggested timeline for the 2-week sprint, breaking down the tasks into daily goals. (Adjustments can be made based on team velocity, but this provides a trackable plan.) Week 1:
Day 1-2: Finalize the data model changes and job scaffolding.
Add the new relationship properties (w_hebb, w_recent, etc.) in the data model definitions.
Write initial Cypher queries or pseudo-code for updating CO_OCCURS and NEXT edges. Test these queries on a small sample graph to ensure they do what is expected (e.g., run on a dev Neo4j with a couple of episodes).
Set up the skeleton for the nightly job in code (perhaps a Python script using a Neo4j driver or an APOC script).
Verify that merging relationships and setting properties works without performance issues on small scale.
Day 3-4: Implement integration with Simulator and Flow Builder, and draft API endpoints.
Modify the simulator code to use w_final. Test the simulator manually or with unit tests using dummy data to confirm it picks up weights.
Modify the flow builder calculation for probabilities.
Implement the two API endpoints (without full optimization yet). Make sure they return the expected data from a test instance.
By end of Day 4, basic end-to-end functionality is in place: one can run the job on sample data, then call the API and see weights, and run the simulator to see it using those weights.
Day 5-6: Focus on testing, refinement, and performance tuning.
Write the unit tests for the math logic and ensure all pass.
Run an integration test of the job on a dataset of, say, a few hundred episodes to gauge performance. Profile query times, and add indexes if needed (e.g., index on AttackPattern.stix_id if not already).
Tune parameters if initial tests show issues (e.g., if consolidation_floor is too high or low, adjust; if recent_alpha should be tweaked for stability).
Ensure the job completes quickly on the tested dataset. If any query is slow, consider splitting it or using periodic commit.
Finalize API output format and test with front-end or a colleague for feedback (make sure it’s usable).
By end of Week 1, we should have a solid implementation for the Hebbian update path and all critical integration points, with tests and basic docs done for those.
Week 2:
Day 7-8: (Optional Stretch) Implement and experiment with the GNN prior.
If proceeding, use these days to build the GraphSAGE model on a sample of the graph. Possibly use an existing library to expedite.
Train on available data (if using real data, perhaps run on a smaller subset or off-hours data export).
Evaluate whether the GNN predictions make sense (spot-check some high-prediction edges to see if they align with domain intuition).
Integrate the blending of w_gnn into the job (behind the enable_gnn flag).
If this is too time-consuming or risky to finish, decide whether to defer it. Even if deferred, ensure the infrastructure (like storing w_gnn property and having the flag) is in place so it can be added later seamlessly.
Day 9-10: Documentation, final adjustments, and QA.
Write and polish the documentation (SPRINT6_PLASTICITY.md) explaining how everything works. Include examples and perhaps figures if useful (e.g., a diagram of how weights flow or how two techniques connect).
Conduct a thorough QA: run the nightly job on a full set of test data that mimics production scale (if possible). Verify the performance criteria (should finish < 5 minutes). Verify memory or transaction log is not an issue in Neo4j.
Check the simulator on some corner cases (for example, an episode where a technique has no next technique with weight – does it handle properly?).
Ensure all tests are passing and add any new tests for things discovered.
If GNN was implemented, verify that running it doesn’t blow up the timeline (maybe it’s fine if training is say 30 minutes offline – since it’s weekly, but just note it).
Prepare release notes and communicate to the team that the feature is ready for release.
Throughout the timeline, adjust as necessary if some tasks take longer; for example, if the job performance needs extra optimization, that might cut into the optional GNN work (which is acceptable to defer). The timeline is a guideline to keep the work on track for the two-week window.
Expected Outcomes and Benefits
By following this plan, we expect to achieve the following outcomes:
Evidence-Preserving Technique Links: The relationships between attack techniques will now encode both short-term and long-term evidence of association. This means the system "remembers" historical co-occurrences and sequences while still adapting to new data. Edges won’t be overly skewed by just the most recent activity (mitigating recency bias), thanks to the dual timescale (recent vs. long) blending.
Stability in Simulation: The Attack Simulator will produce more stable and realistic attack paths. When a particular sequence has been observed consistently (even if not in the very latest data), the simulator will still consider it due to the retained long-term weight. Conversely, one-off spurious sequences will decay over time and not linger indefinitely. Overall, the simulation should be less jittery from day to day and more aligned with true probabilities.
Intelligent Handling of Sparse Data: For techniques that are new or rarely seen (isolated nodes in the graph), the system will not leave them completely disconnected. The tactic-based imputed weight gives a small nudge to connect techniques that should be related (e.g., an Initial Access technique often followed by Execution techniques will get a base weight). If enabled, the GNN prior further enhances this by using graph learning to suggest likely connections based on learned patterns in the data. This means the simulator can still explore plausible attack paths involving those techniques, providing better coverage.
Defense-Aware Probabilities: By incorporating D3FEND countermeasure knowledge, any attack techniques that are well-defended will have a lower weight to succeeding techniques. This effectively biases the simulation to either avoid or de-emphasize sequences that run into strong defenses, or at least mark them as less likely. This can lead to more realistic outputs or help highlight where an attack path might fail due to defenses (useful for analysis).
Observability and Debugging: The introduction of weight inspection APIs and logging means we have greater visibility into why the simulator is choosing certain paths. Stakeholders can query a technique and see “What are the most likely next steps according to our model?” and get an explanation in terms of evidence. This transparency will help in validating the model and building trust, as well as diagnosing if something seems off (we can see if maybe a weight is unexpectedly high or low and trace back the cause).
Performance within Limits: The design and queries are intended to be efficient. Using Neo4j’s ability to do set-based operations and merges, the nightly job should scale to large numbers of episodes. By focusing on top connections in APIs, we avoid transferring huge amounts of data unnecessarily. The expectation (per acceptance criteria) is that the nightly job handles on the order of 100k actions across 10k episodes in a few minutes, which seems feasible with proper indexing and moderate hardware. The weekly GNN job, if used, is heavier but infrequent; it’s effectively doing an offline training that can be managed separately.
In summary, this execution plan lays out a comprehensive approach to enhance the simulation engine with biologically-inspired Hebbian learning mechanisms and modern graph ML techniques, all while ensuring the solution is trackable, testable, and tunable. Following this plan will result in a more adaptive and robust attack technique graph that improves the fidelity of simulations and analyses going forward.


