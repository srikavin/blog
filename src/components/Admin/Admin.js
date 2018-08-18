import React from 'react';
import PropTypes from 'prop-types';
import {Route, Switch} from 'react-router-dom';
import Editor from './PostEditor/Editor/Editor';
import Creator from './PostEditor/Creator/Creator';
import Dashboard from './Dashboard/Dashboard';

class Admin extends React.Component {
    render() {
        return (
            <Switch>
                <Route exact path="/admin/edit/:id" component={Editor}/>
                <Route exact path="/admin/posts/new" component={Creator}/>
                <Route component={Dashboard}/>
            </Switch>
        )
    }
}

Admin.propTypes = {
    from: PropTypes.string
};

export default Admin;