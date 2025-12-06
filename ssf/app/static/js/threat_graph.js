let cyInstance = null;

function loadThreatModel() {
    const container = document.getElementById('threat-graph-container');

    
    if (cyInstance) {
        console.log('Destroying previous Cytoscape instance');
        try {
            cyInstance.destroy();
        } catch (e) {
            console.warn('Error destroying previous instance:', e);
        }
        cyInstance = null;
    }

    container.innerHTML = '';

    console.log('loadThreatModel called');
    console.log('currentReport:', currentReport);

    if (!currentReport || !currentReport.threat_model) {
        console.log('No threat model found in currentReport');
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🕸️</div>
                <h3>No Threat Model Found</h3>
                <p>Run a scan with AI enabled and --threat-model flag to generate one.</p>
            </div>`;
        return;
    }
    console.log('Threat model data found:', currentReport.threat_model);

    const tm = currentReport.threat_model;
    const elements = [];

    if (tm.threat_actors) {
        tm.threat_actors.forEach((actor, i) => {
            elements.push({
                data: { id: `actor_${i}`, label: actor, type: 'actor' }
            });
        });
    }

    if (tm.assets) {
        tm.assets.forEach((asset, i) => {
            elements.push({
                data: { id: `asset_${i}`, label: asset, type: 'asset' }
            });
        });
    }

    if (tm.attack_paths) {
        tm.attack_paths.forEach((path, i) => {

            const attackId = `attack_${i}`;
   
            let label = path.name;
            if (label.length > 20) label = label.substring(0, 20) + '...';

            elements.push({
                data: {
                    id: attackId,
                    label: label,
                    fullLabel: path.name, 
                    type: 'attack',
                    impact: path.impact,
                    likelihood: path.likelihood
                }
            });


            if (tm.threat_actors && tm.threat_actors.length > 0) {
                elements.push({
                    data: { source: `actor_0`, target: attackId, label: 'Initiates' }
                });
            }


            if (tm.assets) {
                tm.assets.forEach((asset, ai) => {
                    if (path.description.toLowerCase().includes(asset.toLowerCase()) ||
                        path.name.toLowerCase().includes(asset.toLowerCase())) {
                        elements.push({
                            data: { source: attackId, target: `asset_${ai}`, label: 'Compromises' }
                        });
                    }
                });
            }
        });
    }


    console.log('Generated elements:', JSON.stringify(elements, null, 2));
    console.log('Container dimensions:', container.offsetWidth, 'x', container.offsetHeight);

    if (container.offsetWidth === 0 || container.offsetHeight === 0) {
        console.warn('Container has no size! Graph will not be visible.');
        container.style.height = '600px'; 
        container.style.width = '100%';
        console.log('Forced container dimensions');
    }

    if (typeof cytoscape === 'undefined') {
        console.error('Cytoscape library not loaded!');
        container.innerHTML = '<p class="error">Error: Cytoscape library not loaded.</p>';
        return;
    }

    try {
        console.log('Initializing Cytoscape...');
        cyInstance = cytoscape({
            container: container,
            elements: elements,
            style: [
   
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'text-valign': 'bottom',
                        'text-halign': 'center',
                        'text-margin-y': 8,
                        'color': '#cbd5e1',
                        'font-family': 'Outfit, sans-serif',
                        'font-size': '11px',
                        'font-weight': 500,
                        'text-wrap': 'wrap',
                        'text-max-width': '100px',
                        'text-background-color': '#1e293b',
                        'text-background-opacity': 0.8,
                        'text-background-padding': '4px',
                        'text-background-shape': 'roundrectangle',
                        'background-color': '#475569',
                        'border-width': 2,
                        'border-color': '#334155',
                        'overlay-opacity': 0
                    }
                },
           
                {
                    selector: 'node[type="actor"]',
                    style: {
                        'background-color': '#be123c',
                        'border-color': '#f43f5e',
                        'shape': 'diamond',
                        'width': 50,
                        'height': 50
                    }
                },
         
                {
                    selector: 'node[type="asset"]',
                    style: {
                        'background-color': '#0369a1',
                        'border-color': '#0ea5e9',
                        'shape': 'round-rectangle',
                        'width': 60,
                        'height': 60
                    }
                },
               
                {
                    selector: 'node[type="attack"]',
                    style: {
                        'background-color': '#a16207',
                        'border-color': '#eab308',
                        'shape': 'triangle',
                        'width': 40,
                        'height': 40
                    }
                },
              
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#475569',
                        'target-arrow-color': '#475569',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '9px',
                        'color': '#94a3b8',
                        'text-rotation': 'autorotate',
                        'text-background-color': '#0f172a',
                        'text-background-opacity': 0.8,
                        'text-background-padding': 2
                    }
                }
            ],
            layout: {
                name: 'breadthfirst',
                directed: true,
                padding: 50,
                spacingFactor: 1.5,
                animate: true,
                animationDuration: 500,
                avoidOverlap: true
            }
        });


        cyInstance.on('tap', 'node', function (evt) {
            const node = evt.target;
            if (node.data('type') === 'attack') {
                alert(`Attack: ${node.data('label')}\nImpact: ${node.data('impact')}\nLikelihood: ${node.data('likelihood')}`);
            }
        });

        console.log('Cytoscape initialized successfully');


        setTimeout(() => {
            if (cyInstance) {
                console.log('Forcing resize and fit (500ms)');
                cyInstance.resize();
                cyInstance.fit();
            }
        }, 500);

    } catch (e) {
        console.error('Error initializing Cytoscape:', e);
        container.innerHTML = `<p class="error">Error initializing graph: ${e.message}</p>`;
    }
}
