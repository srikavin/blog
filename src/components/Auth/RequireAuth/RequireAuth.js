import React from 'react';
import PropTypes from 'prop-types';
import Auth from '../../../util/AuthController';
import {Redirect} from 'react-router-dom';

class RequireAuth extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    componentDidMount() {
    }

    render() {
        if (Auth.getInstance().isLoggedIn()) {
            return null;
        }
        return <Redirect to={{pathname: '/login', state: {from: this.props.from}}}/>
    }
}

RequireAuth.propTypes = {
    from: PropTypes.string.isRequired
};

export default RequireAuth;