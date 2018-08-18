import React, {Component} from 'react';
import {PostStore} from '../../../../../data/resource/post';
import PostCrudList from '../../PostManager/PostCrudList/PostCrudList';

class DraftList extends Component {
    constructor(props) {
        super(props);
        this.state = {
            posts: []
        };
    }


    componentDidMount() {
        PostStore.getAllDrafts().then(e => {
            this.setState({
                posts: e
            });
        })
    }

    render() {
        return (
            <PostCrudList updateItems={(posts) => this.setState({posts})} items={this.state.posts}/>
        );
    }
}

DraftList.propTypes = {};

export default DraftList;