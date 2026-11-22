use pyo3::prelude::*;
use rayon::prelude::*;

/// A partir de este número de nodos la repulsión se reparte entre hilos (por debajo, el bucle por pares secuencial
/// es más rápido: la versión por nodo hace el doble de cálculos). Ambos caminos dan el mismo resultado bit a bit.
const PAR_MIN_NODES: usize = 256;

/// Norma euclídea con la MISMA expresión que el fallback Python: `sqrt(dx*dx + dy*dy)`.
///
/// Multiplicación, suma y raíz son operaciones IEEE-754 con redondeo exacto y Rust no las fusiona en FMA, así que
/// ambos lados producen el mismo resultado bit a bit. (`f64::hypot` y `math.hypot` dependen de la libm y difieren
/// en el último bit; Fruchterman-Reingold amplifica esa diferencia hasta cientos de píxeles.)
#[inline]
fn norm(dx: f64, dy: f64) -> f64 {
    (dx * dx + dy * dy).sqrt()
}

/// Repulsión secuencial por pares (i < j), exactamente en el orden del fallback Python.
fn repulsion_pairwise(pos: &[[f64; 2]], k2: f64) -> Vec<[f64; 2]> {
    let n = pos.len();
    let mut disp = vec![[0.0_f64, 0.0_f64]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let dx = pos[i][0] - pos[j][0];
            let dy = pos[i][1] - pos[j][1];
            let mut dist = norm(dx, dy);
            if dist == 0.0 {
                dist = 0.01;
            }
            let force = k2 / dist;
            let fx = (dx / dist) * force;
            let fy = (dy / dist) * force;
            disp[i][0] += fx;
            disp[i][1] += fy;
            disp[j][0] -= fx;
            disp[j][1] -= fy;
        }
    }
    disp
}

/// Repulsión acumulada sobre el nodo `m` en el MISMO orden que la versión secuencial por pares: las
/// contribuciones llegan con k = 0..n creciente (primero los pares (k, m) con k < m, luego los (m, k)).
/// Calcularla por nodo permite paralelizar sin alterar el orden de las sumas: resultado idéntico bit a bit.
fn repulsion_for(m: usize, pos: &[[f64; 2]], k2: f64) -> [f64; 2] {
    let (xm, ym) = (pos[m][0], pos[m][1]);
    let mut acc = [0.0_f64, 0.0_f64];
    for (k, p) in pos.iter().enumerate() {
        if k == m {
            continue;
        }
        let (dx, dy) = if k < m {
            (p[0] - xm, p[1] - ym)
        } else {
            (xm - p[0], ym - p[1])
        };
        let mut dist = norm(dx, dy);
        if dist == 0.0 {
            dist = 0.01;
        }
        let force = k2 / dist;
        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        if k < m {
            // par (k, m) en la versión secuencial: disp[m] -= fx
            acc[0] -= fx;
            acc[1] -= fy;
        } else {
            // par (m, k): disp[m] += fx
            acc[0] += fx;
            acc[1] += fy;
        }
    }
    acc
}

fn compute(
    n: usize,
    edges: &[(usize, usize)],
    initial_pos: Vec<(f64, f64)>,
    iterations: usize,
) -> Vec<(f64, f64)> {
    if n == 0 {
        return Vec::new();
    }
    let mut pos: Vec<[f64; 2]> = initial_pos.into_iter().map(|(x, y)| [x, y]).collect();
    pos.resize(n, [0.0, 0.0]);

    let nf = n as f64;
    let area = nf * 40000.0;
    let k = (area / nf).sqrt();
    let k2 = k * k;
    let mut temp = area.sqrt() / 10.0;

    for _ in 0..iterations {
        // 1. Repulsión entre todos los pares: por nodo y en paralelo si el grafo es grande; si no, por pares
        let mut disp: Vec<[f64; 2]> = if n >= PAR_MIN_NODES {
            (0..n)
                .into_par_iter()
                .map(|m| repulsion_for(m, &pos, k2))
                .collect()
        } else {
            repulsion_pairwise(&pos, k2)
        };

        // 2. Atracción a lo largo de las aristas, en el orden recibido (el mismo que el fallback Python)
        for &(u, v) in edges {
            if u < n && v < n {
                let dx = pos[u][0] - pos[v][0];
                let dy = pos[u][1] - pos[v][1];
                let mut dist = norm(dx, dy);
                if dist == 0.0 {
                    dist = 0.01;
                }
                let force = (dist * dist) / k;
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                disp[u][0] -= fx;
                disp[u][1] -= fy;
                disp[v][0] += fx;
                disp[v][1] += fy;
            }
        }

        // 3. Desplazamiento con límite térmico
        for i in 0..n {
            let mut d = norm(disp[i][0], disp[i][1]);
            if d == 0.0 {
                d = 0.01;
            }
            let step = if d < temp { d } else { temp };
            pos[i][0] += (disp[i][0] / d) * step;
            pos[i][1] += (disp[i][1] / d) * step;
        }

        // 4. Enfriamiento
        temp *= 0.95;
    }

    pos.into_iter().map(|p| (p[0], p[1])).collect()
}

/// Layout Fruchterman-Reingold determinista, idéntico bit a bit a `mtgx._force_py`.
///
/// - `nodes`: identificadores ordenados (solo se usa su número; el orden lo fija el llamador).
/// - `edges`: pares (u, v) con u < v, en el mismo orden en que los recorre el fallback Python.
/// - `initial_pos`: posiciones iniciales (layout radial) en el orden de `nodes`.
///
/// Libera el GIL durante el cálculo: el event loop y otros hilos de Python siguen ejecutándose.
#[pyfunction]
pub fn force_layout(
    py: Python<'_>,
    nodes: Vec<String>,
    edges: Vec<(usize, usize)>,
    initial_pos: Vec<(f64, f64)>,
    iterations: usize,
) -> PyResult<Vec<(f64, f64)>> {
    let n = nodes.len();
    Ok(py.allow_threads(move || compute(n, &edges, initial_pos, iterations)))
}
