const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========================================
// CONFIGURACIÓN DE BASE DE DATOS
// ========================================

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'cegae_db',
    password: process.env.DB_PASSWORD || 'password',
    port: process.env.DB_PORT || 5432,
});


// ========================================
// MIDDLEWARE DE AUTENTICACIÓN
// ========================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'tu_secret_key_aqui', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// ========================================
// RUTAS DE AUTENTICACIÓN
// ========================================

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Verificar credenciales desde variables de entorno
        const ADMIN_USER = process.env.ADMIN_USER || 'admin';
        const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
        
        if (username !== ADMIN_USER || password !== ADMIN_PASSWORD) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        // Generar token JWT
        const token = jwt.sign(
            { username, role: 'admin' },
            process.env.JWT_SECRET || 'tu_secret_key_aqui',
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { username, role: 'admin' },
            message: 'Login exitoso' 
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Verificar token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ========================================
// RUTAS PARA ESTADOS
// ========================================

// Obtener todos los estados
app.get('/api/estados', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM cegae_estados ORDER BY idestado'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener estados:', error);
        res.status(500).json({ error: 'Error al obtener estados' });
    }
});

// ========================================
// RUTAS PARA CURSOS
// ========================================

// Obtener todos los cursos
app.get('/api/cursos', authenticateToken, async (req, res) => {
    try {
        

        const { search, estado } = req.query;
        let query = `
            SELECT c.*, e.nombre as estado_nombre 
            FROM cegae_cursosdisponibles c
            LEFT JOIN cegae_estados e ON c.idestado = e.idestado
            WHERE c.idestado = 1
        `;
        const params = [];
        if (search) {
            params.push(`%${search}%`);
            query += ` AND (c.nombre_curso ILIKE $${params.length} 
                       OR c.descripcion ILIKE $${params.length})`;
        }
        //console.log("estado", estado);
        // if (estado) {
        //     params.push(estado);
        //     query += ` AND c.idestado = $${params.length}`;
        // }
        
        query += ' ORDER BY c.idcurso DESC';
        
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).json({ error: 'Error al obtener cursos' });
    }
});

// Obtener un curso por ID
app.get('/api/cursos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT c.*, e.nombre as estado_nombre 
             FROM cegae_cursosdisponibles c
             LEFT JOIN cegae_estados e ON c.idestado = e.idestado
             WHERE c.idcurso = $1`,
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Curso no encontrado' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al obtener curso:', error);
        res.status(500).json({ error: 'Error al obtener curso' });
    }
});

// Crear nuevo curso
app.post('/api/cursos', authenticateToken, async (req, res) => {
    try {
        const {
            nombre_curso,
            descripcion,
            dirigido,
            horas_clases_por_dia,
            horarios,
            frecuencia,
            idestado
        } = req.body;
        
        // Validación básica
        if (!nombre_curso) {
            return res.status(400).json({ error: 'El nombre del curso es requerido' });
        }
        
        const result = await pool.query(
            `INSERT INTO cegae_cursosdisponibles 
             (nombre_curso, descripcion, dirigido, horas_clases_por_dia, 
              horarios, frecuencia, idestado)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [nombre_curso, descripcion, dirigido, horas_clases_por_dia, 
             horarios, frecuencia, idestado || 1]
        );
        
        res.status(201).json({
            message: 'Curso creado exitosamente',
            curso: result.rows[0]
        });
    } catch (error) {
        console.error('Error al crear curso:', error);
        res.status(500).json({ error: 'Error al crear curso' });
    }
});

// Actualizar curso
app.put('/api/cursos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            nombre_curso,
            descripcion,
            dirigido,
            horas_clases_por_dia,
            horarios,
            frecuencia,
            idestado
        } = req.body;
        
        const result = await pool.query(
            `UPDATE cegae_cursosdisponibles 
             SET nombre_curso = $1, 
                 descripcion = $2, 
                 dirigido = $3, 
                 horas_clases_por_dia = $4,
                 horarios = $5, 
                 frecuencia = $6, 
                 idestado = $7,
                 fechaedicion = CURRENT_TIMESTAMP
             WHERE idcurso = $8
             RETURNING *`,
            [nombre_curso, descripcion, dirigido, horas_clases_por_dia, 
             horarios, frecuencia, idestado, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Curso no encontrado' });
        }
        
        res.json({
            message: 'Curso actualizado exitosamente',
            curso: result.rows[0]
        });
    } catch (error) {
        console.error('Error al actualizar curso:', error);
        res.status(500).json({ error: 'Error al actualizar curso' });
    }
});

// Eliminar curso (soft delete)
app.delete('/api/cursos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Verificar si hay ciclos asociados
        const ciclosCheck = await pool.query(
            'SELECT COUNT(*) FROM cegae_cursosdisponiblesciclo WHERE idcurso = $1 and idestado = 1',
            [id]
        );
        
        if (parseInt(ciclosCheck.rows[0].count) > 0) {
            return res.status(400).json({ 
                error: 'No se puede eliminar el curso porque tiene ciclos asociados' 
            });
        }
        
        // Soft delete: marcar como anulado
        const result = await pool.query(
            `UPDATE cegae_cursosdisponibles 
             SET idestado = 2, 
                 fechaanulacion = CURRENT_TIMESTAMP 
             WHERE idcurso = $1
             RETURNING *`,
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Curso no encontrado' });
        }
        
        res.json({ message: 'Curso eliminado exitosamente' });
    } catch (error) {
        console.error('Error al eliminar curso:', error);
        res.status(500).json({ error: 'Error al eliminar curso' });
    }
});

// ========================================
// RUTAS PARA CICLOS
// ========================================

// Obtener todos los ciclos
app.get('/api/ciclos', authenticateToken, async (req, res) => {
    try {
        const { search, idcurso, estado } = req.query;
        let query = `
            SELECT ci.*, cu.nombre_curso, e.nombre as estado_nombre 
            FROM cegae_cursosdisponiblesciclo ci
            INNER JOIN cegae_cursosdisponibles cu ON ci.idcurso = cu.idcurso
            LEFT JOIN cegae_estados e ON ci.idestado = e.idestado
            WHERE  ci.idestado =1 
        `;
        const params = [];
        
        if (search) {
            params.push(`%${search}%`);
            query += ` AND ci.nombreciclo ILIKE $${params.length}`;
        }
        
        if (idcurso) {
            params.push(idcurso);
            query += ` AND ci.idcurso = $${params.length}`;
        }
        
        // if (estado) {
        //     params.push(estado);
        //     query += ` AND ci.idestado = $${params.length}`;
        // }
        
        query += ' ORDER BY ci.idcurso DESC';
        
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener ciclos:', error);
        res.status(500).json({ error: 'Error al obtener ciclos' });
    }
});

// Obtener un ciclo por ID
app.get('/api/ciclos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT ci.*, cu.nombre_curso, e.nombre as estado_nombre 
             FROM cegae_cursosdisponiblesciclo ci
             INNER JOIN cegae_cursosdisponibles cu ON ci.idcurso = cu.idcurso
             LEFT JOIN cegae_estados e ON ci.idestado = e.idestado
             WHERE ci.idciclo = $1`,
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Ciclo no encontrado' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al obtener ciclo:', error);
        res.status(500).json({ error: 'Error al obtener ciclo' });
    }
});

// Crear nuevo ciclo
app.post('/api/ciclos', authenticateToken, async (req, res) => {
    try {
        const {
            idcurso,
            nombreciclo,
            precio_regular,
            precio_promocion,
            fecha_inicio_clase,
            fecha_fin_clase,
            duracion_curso_total,
            idestado
        } = req.body;
        
        // Validación básica
        if (!idcurso || !nombreciclo) {
            return res.status(400).json({ 
                error: 'El curso y nombre del ciclo son requeridos' 
            });
        }
        
        // Verificar que el curso existe
        const cursoCheck = await pool.query(
            'SELECT idcurso FROM cegae_cursosdisponibles WHERE idcurso = $1',
            [idcurso]
        );
        
        if (cursoCheck.rows.length === 0) {
            return res.status(400).json({ error: 'El curso especificado no existe' });
        }
        
        const result = await pool.query(
            `INSERT INTO cegae_cursosdisponiblesciclo 
             (idcurso, nombreciclo, precio_regular, precio_promocion, 
              fecha_inicio_clase, fecha_fin_clase, duracion_curso_total, idestado)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *`,
            [idcurso, nombreciclo, precio_regular, precio_promocion, 
             fecha_inicio_clase, fecha_fin_clase, duracion_curso_total, idestado || 1]
        );
        
        res.status(201).json({
            message: 'Ciclo creado exitosamente',
            ciclo: result.rows[0]
        });
    } catch (error) {
        console.error('Error al crear ciclo:', error);
        res.status(500).json({ error: 'Error al crear ciclo' });
    }
});

// Actualizar ciclo
app.put('/api/ciclos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            idcurso,
            nombreciclo,
            precio_regular,
            precio_promocion,
            fecha_inicio_clase,
            fecha_fin_clase,
            duracion_curso_total,
            idestado
        } = req.body;
        
        const result = await pool.query(
            `UPDATE cegae_cursosdisponiblesciclo 
             SET idcurso = $1,
                 nombreciclo = $2,
                 precio_regular = $3,
                 precio_promocion = $4,
                 fecha_inicio_clase = $5,
                 fecha_fin_clase = $6,
                 duracion_curso_total = $7,
                 idestado = $8,
                 fechaedicion = CURRENT_TIMESTAMP
             WHERE idciclo = $9
             RETURNING *`,
            [idcurso, nombreciclo, precio_regular, precio_promocion, 
             fecha_inicio_clase, fecha_fin_clase, duracion_curso_total, 
             idestado, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Ciclo no encontrado' });
        }
        
        res.json({
            message: 'Ciclo actualizado exitosamente',
            ciclo: result.rows[0]
        });
    } catch (error) {
        console.error('Error al actualizar ciclo:', error);
        res.status(500).json({ error: 'Error al actualizar ciclo' });
    }
});

// Eliminar ciclo (soft delete)
app.delete('/api/ciclos/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
         
        // Soft delete: marcar como anulado
        const result = await pool.query(
            `UPDATE cegae_cursosdisponiblesciclo 
             SET idestado = 2, 
                 fechaanulacion = CURRENT_TIMESTAMP 
             WHERE idciclo = $1
             RETURNING *`,
            [id]
        );
         
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Ciclo no encontrado' });
        }
        
        res.json({ message: 'Ciclo eliminado exitosamente' });
    } catch (error) {
        console.error('Error al eliminar ciclo:', error);
        res.status(500).json({ error: 'Error al eliminar ciclo' });
    }
});

// ========================================
// RUTAS DE ESTADÍSTICAS Y REPORTES
// ========================================

// Obtener estadísticas generales
app.get('/api/estadisticas', authenticateToken, async (req, res) => {
    try {
        const stats = {};
        
        // Total de cursos activos
        const cursosActivos = await pool.query(
            'SELECT COUNT(*) FROM cegae_cursosdisponibles WHERE idestado = 1'
        );
        stats.cursosActivos = parseInt(cursosActivos.rows[0].count);
        
        // Total de ciclos activos
        const ciclosActivos = await pool.query(
            'SELECT COUNT(*) FROM cegae_cursosdisponiblesciclo WHERE idestado = 1'
        );
        stats.ciclosActivos = parseInt(ciclosActivos.rows[0].count);
        
        // Ciclos próximos a iniciar (próximos 30 días)
        const ciclosProximos = await pool.query(
            `SELECT COUNT(*) FROM cegae_cursosdisponiblesciclo 
             WHERE fecha_inicio_clase BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '30 days'
             AND idestado = 1`
        );
        stats.ciclosProximos = parseInt(ciclosProximos.rows[0].count);
        
        // Ciclos en curso
        const ciclosEnCurso = await pool.query(
            `SELECT COUNT(*) FROM cegae_cursosdisponiblesciclo 
             WHERE CURRENT_DATE BETWEEN fecha_inicio_clase AND fecha_fin_clase
             AND idestado = 1`
        );
        stats.ciclosEnCurso = parseInt(ciclosEnCurso.rows[0].count);
        
        res.json(stats);
    } catch (error) {
        console.error('Error al obtener estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});


// ==========================================
// ENDPOINTS PARA GESTIÓN DE INTERESADOS
// ==========================================

// Obtener todos los interesados con filtros opcionales
app.get('/api/interesados', authenticateToken, async (req, res) => {
    try {
        const { search, curso, pago, proceso } = req.query;
        
        let query = `
            SELECT 
                id,
                nombres_completos,
                correo,
                celular,
                curso_interesado,
                ciclo_interesado,
                realizo_el_pago,
                is_atendido_por_humano,
                urlvoucherpago,
                nrocelularadicional,
                departamento,
                nombreasesora,
                registradoengrupoflag,
                brindadousuariosflag,
                comentario,
                procesoincripcionterminadoflag,
                fechacrea
            FROM cegae_interesados_curso
            WHERE idestado=1
        `;
        
        const params = [];
        let paramCount = 1;
        
        // Filtro de búsqueda por nombre o celular
        if (search) {
            query += ` AND (nombres_completos ILIKE $${paramCount} OR celular ILIKE $${paramCount})`;
            params.push(`%${search}%`);
            paramCount++;
        }
        
        // Filtro por curso
        if (curso) {
            query += ` AND curso_interesado = $${paramCount}`;
            params.push(curso);
            paramCount++;
        }
        
        // Filtro por estado de pago
        if (pago !== undefined && pago !== '') {
            query += ` AND realizo_el_pago = $${paramCount}`;
            params.push(pago === '1' || pago === 'true');
            paramCount++;
        }
        
        // Filtro por proceso terminado
        if (proceso !== undefined && proceso !== '') {
            query += ` AND procesoincripcionterminadoflag = $${paramCount}`;
            params.push(proceso === '1' || proceso === 'true');
            paramCount++;
        }
        
        query += ` ORDER BY fechacrea DESC`;
        
        const result = await pool.query(query, params);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener interesados:', error);
        res.status(500).json({ error: 'Error al obtener interesados' });
    }
});

// Obtener un interesado por ID
app.get('/api/interesados/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT * FROM cegae_interesados_curso WHERE id = $1`,
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Interesado no encontrado' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al obtener interesado:', error);
        res.status(500).json({ error: 'Error al obtener interesado' });
    }
});

// Actualizar interesado (solo campos editables)
app.put('/api/interesados/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            realizo_el_pago,
            is_atendido_por_humano,
            urlvoucherpago,
            nrocelularadicional,
            departamento,
            nombreasesora,
            registradoengrupoflag,
            brindadousuariosflag,
            comentario,
            procesoincripcionterminadoflag
        } = req.body;
        
        // Verificar que el interesado existe
        const checkResult = await pool.query(
            'SELECT id FROM cegae_interesados_curso WHERE id = $1',
            [id]
        );
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Interesado no encontrado' });
        }
        
        const result = await pool.query(
            `UPDATE cegae_interesados_curso 
             SET realizo_el_pago = $1,
                 is_atendido_por_humano = $2,
                 urlvoucherpago = $3,
                 nrocelularadicional = $4,
                 departamento = $5,
                 nombreasesora = $6,
                 registradoengrupoflag = $7,
                 brindadousuariosflag = $8,
                 comentario = $9,
                 procesoincripcionterminadoflag = $10
             WHERE id = $11
             RETURNING *`,
            [
                realizo_el_pago,
                is_atendido_por_humano,
                urlvoucherpago || null,
                nrocelularadicional || null,
                departamento || null,
                nombreasesora || null,
                registradoengrupoflag,
                brindadousuariosflag,
                comentario || null,
                procesoincripcionterminadoflag,
                id
            ]
        );
        
        res.json({
            message: 'Interesado actualizado exitosamente',
            interesado: result.rows[0]
        });
    } catch (error) {
        console.error('Error al actualizar interesado:', error);
        res.status(500).json({ error: 'Error al actualizar interesado' });
    }
});

// Obtener lista de cursos únicos de los interesados (para el filtro)
app.get('/api/interesados-cursos', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT curso_interesado 
             FROM cegae_interesados_curso 
             WHERE curso_interesado IS NOT NULL 
             ORDER BY curso_interesado`
        );
        
        res.json(result.rows.map(row => row.curso_interesado));
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).json({ error: 'Error al obtener cursos' });
    }
});

// Obtener estadísticas de interesados (opcional - útil para dashboard)
app.get('/api/interesados-stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as con_pago,
                COUNT(CASE WHEN is_atendido_por_humano = 1 THEN 1 END) as atendidos,
                COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END) as terminados,
                COUNT(CASE WHEN registradoengrupoflag = true THEN 1 END) as en_grupo
            FROM cegae_interesados_curso
        `);
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al obtener estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

// Actualizar solo el estado de pago (endpoint rápido)
app.patch('/api/interesados/:id/pago', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { realizo_el_pago, urlvoucherpago } = req.body;
        
        const result = await pool.query(
            `UPDATE cegae_interesados_curso 
             SET realizo_el_pago = $1,
                 urlvoucherpago = $2,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $3
             RETURNING *`,
            [realizo_el_pago, urlvoucherpago || null, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Interesado no encontrado' });
        }
        
        res.json({
            message: 'Estado de pago actualizado',
            interesado: result.rows[0]
        });
    } catch (error) {
        console.error('Error al actualizar pago:', error);
        res.status(500).json({ error: 'Error al actualizar pago' });
    }
});

// Marcar proceso como terminado (endpoint rápido)
app.patch('/api/interesados/:id/terminar', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await pool.query(
            `UPDATE cegae_interesados_curso 
             SET procesoincripcionterminadoflag = true,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $1
             RETURNING *`,
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Interesado no encontrado' });
        }
        
        res.json({
            message: 'Proceso marcado como terminado',
            interesado: result.rows[0]
        });
    } catch (error) {
        console.error('Error al marcar proceso:', error);
        res.status(500).json({ error: 'Error al marcar proceso' });
    }
});







// ==========================================
// ENDPOINT PRINCIPAL DEL DASHBOARD
// ==========================================

app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const { periodo, curso, ciclo } = req.query;
        
        // Construir filtros de fecha según el período
        let dateFilter = '';
        
        switch(periodo) {
            case 'today':
                dateFilter = `AND DATE(fechacrea) = CURRENT_DATE`;
                break;
            case 'week':
                dateFilter = `AND fechacrea >= DATE_TRUNC('week', CURRENT_DATE)`;
                break;
            case 'month':
                dateFilter = `AND fechacrea >= DATE_TRUNC('month', CURRENT_DATE)`;
                break;
            case 'quarter':
                dateFilter = `AND fechacrea >= DATE_TRUNC('quarter', CURRENT_DATE)`;
                break;
            case 'year':
                dateFilter = `AND fechacrea >= DATE_TRUNC('year', CURRENT_DATE)`;
                break;
            default:
                dateFilter = '';
        }
        
        // Filtros adicionales
        let additionalFilters = '';
        const params = [];
        let paramCount = 1;
        
        if (curso) {
            additionalFilters += ` AND curso_interesado = $${paramCount}`;
            params.push(curso);
            paramCount++;
        }
        
        if (ciclo) {
            additionalFilters += ` AND ciclo_interesado = $${paramCount}`;
            params.push(ciclo);
            paramCount++;
        }
        
        const whereClause = `WHERE idestado=1 ${dateFilter} ${additionalFilters}`;
        
        // ====================
        // 1. KPIs PRINCIPALES
        // ====================
        const kpisQuery = `
            SELECT 
                COUNT(*) as total_interesados,
                COUNT(CASE WHEN DATE(fechacrea) = CURRENT_DATE THEN 1 END) as nuevos_hoy,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as total_pagos,
                COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END) as procesos_completados,
                COUNT(CASE WHEN is_atendido_por_humano = 1 THEN 1 END) as atendidos_humano,
                COUNT(CASE WHEN registradoengrupoflag = true THEN 1 END) as en_grupos,
                COUNT(CASE WHEN brindadousuariosflag = true THEN 1 END) as usuarios_brindados
            FROM cegae_interesados_curso
            ${whereClause}
        `;
        
        const kpisResult = await pool.query(kpisQuery, params);
        const kpisData = kpisResult.rows[0];
        
        // Calcular ingresos (asumiendo precio promedio de S/. 500 por ahora)
        // Deberías obtener el precio real desde la tabla de ciclos
        const precioPromedio = 500;
        const ingresosTotales = parseInt(kpisData.total_pagos) * precioPromedio;
        const ticketPromedio = parseInt(kpisData.total_pagos) > 0 
            ? ingresosTotales / parseInt(kpisData.total_pagos) 
            : 0;
        
        const tasaConversion = parseInt(kpisData.total_interesados) > 0
            ? (parseInt(kpisData.total_pagos) / parseInt(kpisData.total_interesados)) * 100
            : 0;
            
        const tasaCompletado = parseInt(kpisData.total_interesados) > 0
            ? (parseInt(kpisData.procesos_completados) / parseInt(kpisData.total_interesados)) * 100
            : 0;
            
        const porcentajeAtendidos = parseInt(kpisData.total_interesados) > 0
            ? (parseInt(kpisData.atendidos_humano) / parseInt(kpisData.total_interesados)) * 100
            : 0;
            
        const porcentajeGrupos = parseInt(kpisData.total_interesados) > 0
            ? (parseInt(kpisData.en_grupos) / parseInt(kpisData.total_interesados)) * 100
            : 0;
            
        const porcentajeUsuarios = parseInt(kpisData.total_interesados) > 0
            ? (parseInt(kpisData.usuarios_brindados) / parseInt(kpisData.total_interesados)) * 100
            : 0;
        
        const kpis = {
            total_interesados: parseInt(kpisData.total_interesados),
            nuevos_hoy: parseInt(kpisData.nuevos_hoy),
            total_pagos: parseInt(kpisData.total_pagos),
            tasa_conversion: tasaConversion,
            ingresos_totales: ingresosTotales,
            ticket_promedio: ticketPromedio,
            procesos_completados: parseInt(kpisData.procesos_completados),
            tasa_completado: tasaCompletado,
            atendidos_humano: parseInt(kpisData.atendidos_humano),
            porcentaje_atendidos: porcentajeAtendidos,
            en_grupos: parseInt(kpisData.en_grupos),
            porcentaje_grupos: porcentajeGrupos,
            usuarios_brindados: parseInt(kpisData.usuarios_brindados),
            porcentaje_usuarios: porcentajeUsuarios
        };
        
        // ====================
        // 2. RENDIMIENTO POR ASESORA
        // ====================
        const asesorasQuery = `
            SELECT 
                COALESCE(nombreasesora, 'Sin asignar') as nombre,
                COUNT(*) as total_atendidos,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as total_pagos,
                COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END) as completados,
                CASE 
                    WHEN COUNT(*) > 0 
                    THEN (COUNT(CASE WHEN realizo_el_pago = true THEN 1 END)::float / COUNT(*)::float * 100)
                    ELSE 0 
                END as tasa_conversion,
                CASE 
                    WHEN COUNT(*) > 0 
                    THEN (COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END)::float / COUNT(*)::float * 100)
                    ELSE 0 
                END as tasa_completado
            FROM cegae_interesados_curso
            ${whereClause}
            GROUP BY nombreasesora
            ORDER BY total_pagos DESC, total_atendidos DESC
        `;
        
        const asesorasResult = await pool.query(asesorasQuery, params);
        const asesoras = asesorasResult.rows.map(a => ({
            nombre: a.nombre,
            total_atendidos: parseInt(a.total_atendidos),
            total_pagos: parseInt(a.total_pagos),
            completados: parseInt(a.completados),
            tasa_conversion: parseFloat(a.tasa_conversion),
            tasa_completado: parseFloat(a.tasa_completado),
            ingresos: parseInt(a.total_pagos) * precioPromedio
        }));
        
        // ====================
        // 3. CURSOS MÁS SOLICITADOS
        // ====================
        const cursosQuery = `
            SELECT 
                COALESCE(curso_interesado, 'Sin especificar') as nombre_curso,
                COUNT(*) as total_interesados,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as total_pagos,
                CASE 
                    WHEN COUNT(*) > 0 
                    THEN (COUNT(CASE WHEN realizo_el_pago = true THEN 1 END)::float / COUNT(*)::float * 100)
                    ELSE 0 
                END as tasa_conversion
            FROM cegae_interesados_curso
            ${whereClause}
            GROUP BY curso_interesado
            ORDER BY total_interesados DESC
            LIMIT 10
        `;
        
        const cursosResult = await pool.query(cursosQuery, params);
        const cursos = cursosResult.rows.map(c => ({
            nombre_curso: c.nombre_curso,
            total_interesados: parseInt(c.total_interesados),
            total_pagos: parseInt(c.total_pagos),
            tasa_conversion: parseFloat(c.tasa_conversion),
            ingresos: parseInt(c.total_pagos) * precioPromedio
        }));
        
        // ====================
        // 4. EMBUDO DE CONVERSIÓN
        // ====================
        const embudoQuery = `
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN is_atendido_por_humano = 1 THEN 1 END) as atendidos,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as pagos,
                COUNT(CASE WHEN registradoengrupoflag = true THEN 1 END) as en_grupo,
                COUNT(CASE WHEN brindadousuariosflag = true THEN 1 END) as usuarios,
                COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END) as completados
            FROM cegae_interesados_curso
            ${whereClause}
        `;
        
        const embudoResult = await pool.query(embudoQuery, params);
        const embudoData = embudoResult.rows[0];
        
        const embudo = {
            total: parseInt(embudoData.total),
            atendidos: parseInt(embudoData.atendidos),
            pagos: parseInt(embudoData.pagos),
            en_grupo: parseInt(embudoData.en_grupo),
            usuarios: parseInt(embudoData.usuarios),
            completados: parseInt(embudoData.completados)
        };
        
        // Respuesta final
        res.json({
            kpis,
            asesoras,
            cursos,
            embudo
        });
        
    } catch (error) {
        console.error('Error al obtener datos del dashboard:', error);
        res.status(500).json({ error: 'Error al obtener datos del dashboard' });
    }
});

// ==========================================
// ENDPOINT PARA OBTENER INGRESOS REALES
// (Opcional - si quieres calcular ingresos reales desde ciclos)
// ==========================================

app.get('/api/dashboard/ingresos', authenticateToken, async (req, res) => {
    try {
        const { periodo, curso, ciclo } = req.query;
        
        // Construir filtros similares al endpoint principal
        let dateFilter = '';
        switch(periodo) {
            case 'today':
                dateFilter = `AND DATE(i.fechacrea) = CURRENT_DATE`;
                break;
            case 'week':
                dateFilter = `AND i.fechacrea >= DATE_TRUNC('week', CURRENT_DATE)`;
                break;
            case 'month':
                dateFilter = `AND i.fechacrea >= DATE_TRUNC('month', CURRENT_DATE)`;
                break;
            case 'quarter':
                dateFilter = `AND i.fechacrea >= DATE_TRUNC('quarter', CURRENT_DATE)`;
                break;
            case 'year':
                dateFilter = `AND i.fechacrea >= DATE_TRUNC('year', CURRENT_DATE)`;
                break;
            default:
                dateFilter = '';
        }
        
        let additionalFilters = '';
        const params = [];
        let paramCount = 1;
        
        if (curso) {
            additionalFilters += ` AND i.curso_interesado = $${paramCount}`;
            params.push(curso);
            paramCount++;
        }
        
        if (ciclo) {
            additionalFilters += ` AND i.ciclo_interesado = $${paramCount}`;
            params.push(ciclo);
            paramCount++;
        }
        
        // Query que obtiene ingresos reales cruzando con tabla de ciclos
        const ingresosQuery = `
            SELECT 
                COUNT(CASE WHEN i.realizo_el_pago = true THEN 1 END) as total_pagos,
                COALESCE(SUM(
                    CASE 
                        WHEN i.realizo_el_pago = true 
                        THEN COALESCE(c.precio_promocion, c.precio_regular, 0)
                        ELSE 0 
                    END
                ), 0) as ingresos_totales
            FROM cegae_interesados_curso i
            LEFT JOIN cegae_ciclos c ON i.ciclo_interesado = c.nombreciclo
            WHERE idestado=1 ${dateFilter} ${additionalFilters}
        `;
        
        const result = await pool.query(ingresosQuery, params);
        const data = result.rows[0];
        
        const totalPagos = parseInt(data.total_pagos);
        const ingresosTotales = parseFloat(data.ingresos_totales);
        const ticketPromedio = totalPagos > 0 ? ingresosTotales / totalPagos : 0;
        
        res.json({
            total_pagos: totalPagos,
            ingresos_totales: ingresosTotales,
            ticket_promedio: ticketPromedio
        });
        
    } catch (error) {
        console.error('Error al calcular ingresos:', error);
        res.status(500).json({ error: 'Error al calcular ingresos' });
    }
});

// ==========================================
// ENDPOINT PARA TENDENCIAS (OPCIONAL)
// ==========================================

app.get('/api/dashboard/tendencias', authenticateToken, async (req, res) => {
    try {
        const { periodo = 'month' } = req.query;
        
        let groupBy = '';
        let dateFormat = '';
        
        switch(periodo) {
            case 'week':
                groupBy = `DATE_TRUNC('day', fechacrea)`;
                dateFormat = 'YYYY-MM-DD';
                break;
            case 'month':
                groupBy = `DATE_TRUNC('day', fechacrea)`;
                dateFormat = 'YYYY-MM-DD';
                break;
            case 'year':
                groupBy = `DATE_TRUNC('month', fechacrea)`;
                dateFormat = 'YYYY-MM';
                break;
            default:
                groupBy = `DATE_TRUNC('day', fechacrea)`;
                dateFormat = 'YYYY-MM-DD';
        }
        
        const tendenciasQuery = `
            SELECT 
                TO_CHAR(${groupBy}, '${dateFormat}') as fecha,
                COUNT(*) as total_interesados,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as total_pagos,
                COUNT(CASE WHEN procesoincripcionterminadoflag = true THEN 1 END) as completados
            FROM cegae_interesados_curso
            WHERE idestado= 1 AND fechacrea >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY ${groupBy}
            ORDER BY ${groupBy} ASC
        `;
        
        const result = await pool.query(tendenciasQuery);
        
        res.json(result.rows);
        
    } catch (error) {
        console.error('Error al obtener tendencias:', error);
        res.status(500).json({ error: 'Error al obtener tendencias' });
    }
});

// ==========================================
// ENDPOINT PARA ESTADÍSTICAS POR DEPARTAMENTO
// ==========================================

app.get('/api/dashboard/departamentos', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                COALESCE(departamento, 'Sin especificar') as departamento,
                COUNT(*) as total_interesados,
                COUNT(CASE WHEN realizo_el_pago = true THEN 1 END) as total_pagos,
                CASE 
                    WHEN COUNT(*) > 0 
                    THEN (COUNT(CASE WHEN realizo_el_pago = true THEN 1 END)::float / COUNT(*)::float * 100)
                    ELSE 0 
                END as tasa_conversion
            FROM cegae_interesados_curso
            WHERE idestado = 1 AND departamento IS NOT NULL AND departamento != ''
            GROUP BY departamento
            ORDER BY total_interesados DESC
            LIMIT 15
        `;
        
        const result = await pool.query(query);
        
        res.json(result.rows.map(d => ({
            departamento: d.departamento,
            total_interesados: parseInt(d.total_interesados),
            total_pagos: parseInt(d.total_pagos),
            tasa_conversion: parseFloat(d.tasa_conversion)
        })));
        
    } catch (error) {
        console.error('Error al obtener datos por departamento:', error);
        res.status(500).json({ error: 'Error al obtener datos por departamento' });
    }
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy' });
});


app.get('/', (req, res) => {
    res.status(200).json({ status: 'todo okk' });
});

// ========================================
// INICIALIZACIÓN DEL SERVIDOR
// ========================================

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`SERVER ejecutándose en http://0.0.0.0:${PORT}`);
   
});

// Manejo de errores no capturados
process.on('unhandledRejection', (err) => {
    console.error('❌ Error no manejado:', err);
});